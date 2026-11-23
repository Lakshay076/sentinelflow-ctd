"""
CTD — DNS Query Tracker

Tracks DNS queries made by each source IP over a rolling
window, and calculates statistics used to spot:

  - DGA (Domain Generation Algorithm) domains: malware
    that generates lots of random-looking domain names.
  - DNS tunnelling: hiding data inside DNS queries or
    using high-volume/unusual query types (e.g. TXT/NULL)
    to exfiltrate data or communicate with C2.

Passive metadata analysis only:
  - Character n-gram transition anomaly scoring.
  - Domain lexical anomaly scoring (consonant runs, digit ratios).
  - DNS query-type distribution (A, AAAA, TXT, CNAME, etc.).
  - Query label length and response size tracking.
  - Zero decryption of encrypted DNS (DoH/DoT) and zero active probes.
"""

import math
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Union


# Common English / legitimate domain character bigrams
COMMON_BIGRAMS: Set[str] = {
    # Frequent natural language bigrams
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
    "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
    "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
    "ca", "el", "ta", "la", "ns", "pe", "il", "di", "ge", "no",
    "ho", "pa", "vi", "lo", "un", "so", "we", "ac", "ot", "fo",
    "mo", "ba", "fi", "da", "su", "wa", "pr", "tr", "wh", "cl",
    "pl", "gr", "bl", "sp", "fr", "fl", "gl", "br", "cr", "dr",
    "ap", "op", "ip", "up", "ab", "ob", "ib", "ub", "ag", "og",
    "ig", "ug", "am", "em", "im", "um", "ad", "od", "id", "ud",
    "av", "ov", "iv", "ct", "rt", "lt", "pt", "mp", "nk", "rk",
    "sk", "oo", "ee", "ai", "ay", "ey", "oy", "oa", "au", "ie",
    "ei", "ui", "sh", "ph", "gh", "ck", "qu", "sc", "sm", "sn",
    "sw", "tw", "wr", "sq", "kn", "gn", "ps", "pt", "tz", "ts",
    # Common tech/web domain roots (api, app, dev, net, sys, doc, hub, git, lab, etc.)
    "pi", "pp", "ev", "et", "ys", "oc", "ub", "ws", "ex", "ux",
    "ix", "ox", "ax", "my", "by", "ly", "ry", "ty", "ny", "cy",
    "dy", "fy", "gy", "py", "sy", "wy",
}

# Standard TLDs and public suffixes to ignore during payload lexical analysis
COMMON_TLDS: Set[str] = {
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "ai",
    "co", "uk", "in", "de", "cn", "jp", "fr", "au", "ca", "ru",
    "ch", "it", "nl", "se", "no", "es", "br", "app", "dev", "cloud",
    "internal", "local", "lan", "corp", "home",
}

# Standard IANA DNS Query Type numeric mapping
QTYPE_NAMES: Dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}

HIGH_ENTROPY_THRESHOLD: float = 3.5
MAX_ENTRIES_PER_SOURCE: int = 500


def calculate_entropy(text: str) -> float:
    """
    Shannon entropy of a string in bits per character.

    Real words like "google" score LOW (< 3.0).
    Random strings like "xk29fpqz" score HIGH (>= 3.5).
    """
    if not text:
        return 0.0

    length = len(text)
    counts = defaultdict(int)
    for character in text:
        counts[character] += 1

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_ngram_anomaly(domain: str) -> float:
    """
    Character bigram transition anomaly score in [0.0, 1.0].

    Measures the proportion of character transitions that violate natural
    linguistic and legitimate domain naming conventions.
    Legitimate domains score LOW (0.0 - 0.20).
    Random DGA domains and encoded tunnels score HIGH (0.45 - 1.0).
    """
    labels = [l.lower() for l in domain.split(".") if l and l not in COMMON_TLDS]
    if not labels:
        labels = [domain.lower().replace(".", "")]

    total_transitions = 0
    abnormal_transitions = 0

    for label in labels:
        clean = "".join(c for c in label if c.isalnum())
        if len(clean) < 3:
            continue

        for i in range(len(clean) - 1):
            bg = clean[i:i+2]
            total_transitions += 1

            c1, c2 = bg[0], bg[1]

            # 1. Digit alternating with a consonant (e.g. "7k", "k2", "9q")
            if (c1.isdigit() and c2.isalpha()) or (c1.isalpha() and c2.isdigit()):
                abnormal_transitions += 1
            # 2. Transition not in common bigrams
            elif bg not in COMMON_BIGRAMS:
                # If both are consonants, transition is highly unnatural
                vowels = "aeiouy"
                if c1.isalpha() and c2.isalpha() and c1 not in vowels and c2 not in vowels:
                    abnormal_transitions += 1
                elif c1.isdigit() and c2.isdigit():
                    # Consecutive numbers inside names (e.g. "99", "10") are common, score moderately
                    pass
                else:
                    abnormal_transitions += 0.5

    if total_transitions == 0:
        return 0.0

    return min(abnormal_transitions / total_transitions, 1.0)


def calculate_lexical_anomaly(domain: str) -> float:
    """
    Lexical anomaly score in [0.0, 1.0].

    Evaluates:
    - Longest consecutive consonant runs (>= 5 is highly anomalous)
    - Digit ratio (high proportion of numeric characters)
    - Consonant-to-vowel ratio imbalance
    """
    labels = [l.lower() for l in domain.split(".") if l and l not in COMMON_TLDS]
    if not labels:
        labels = [domain.lower().replace(".", "")]

    scores = []
    for label in labels:
        clean = "".join(c for c in label if c.isalnum())
        length = len(clean)
        if length < 4:
            continue

        score = 0.0
        digits = sum(1 for c in clean if c.isdigit())
        letters = [c for c in clean if c.isalpha()]
        consonants = [c for c in letters if c not in "aeiouy"]

        # 1. Longest consonant run
        curr_run = 0
        max_run = 0
        for c in clean:
            if c.isalpha() and c not in "aeiouy":
                curr_run += 1
                max_run = max(max_run, curr_run)
            else:
                curr_run = 0

        if max_run >= 5:
            score += 0.40
        elif max_run == 4:
            score += 0.20

        # 2. Digit ratio
        digit_ratio = digits / length
        if digit_ratio >= 0.30:
            score += 0.35
        elif digit_ratio >= 0.15:
            score += 0.20

        # 3. Consonant ratio (for labels with >= 5 letters)
        if len(letters) >= 5:
            c_ratio = len(consonants) / len(letters)
            if c_ratio >= 0.85 or c_ratio <= 0.10:
                score += 0.25

        scores.append(min(score, 1.0))

    return max(scores) if scores else 0.0


class DNSTracker:
    """
    Tracks DNS queries and responses over a rolling bounded time window.
    """

    def __init__(self, window_seconds: float = 30.0):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than 0")

        self.window_seconds = window_seconds

        # src_ip -> deque of query dicts
        self.queries = defaultdict(lambda: deque(maxlen=MAX_ENTRIES_PER_SOURCE))

        # src_ip -> deque of response metadata dicts (timestamp, response_bytes)
        self.responses = defaultdict(lambda: deque(maxlen=MAX_ENTRIES_PER_SOURCE))

    def add_query(
        self,
        timestamp: float,
        src_ip: str,
        domain: str,
        qtype: Union[int, str] = 1,
        packet_bytes: int = 0,
        response_bytes: Optional[int] = None,
    ):
        """
        Record a DNS query for a source IP.

        Parameters:
            timestamp: Packet observation timestamp.
            src_ip: Client source IP address.
            domain: Domain name text queried.
            qtype: DNS query type (int or str, e.g. 1 / "A", 16 / "TXT").
            packet_bytes: Size of query packet in bytes.
            response_bytes: Optional response size if immediately available.
        """
        domain = domain.rstrip(".")
        clean_text = domain.replace(".", "")
        entropy = calculate_entropy(clean_text)
        length = len(domain)

        labels = [l for l in domain.split(".") if l]
        max_label_length = max((len(l) for l in labels), default=0)
        mean_label_length = (
            sum(len(l) for l in labels) / max(len(labels), 1)
        )

        ngram_anomaly = calculate_ngram_anomaly(domain)
        lexical_anomaly = calculate_lexical_anomaly(domain)

        if isinstance(qtype, int):
            qtype_str = QTYPE_NAMES.get(qtype, f"TYPE_{qtype}")
        else:
            qtype_str = str(qtype).upper()

        entry = {
            "timestamp": timestamp,
            "domain": domain,
            "entropy": entropy,
            "length": length,
            "max_label_length": max_label_length,
            "mean_label_length": mean_label_length,
            "ngram_anomaly": ngram_anomaly,
            "lexical_anomaly": lexical_anomaly,
            "qtype": qtype_str,
            "packet_bytes": packet_bytes,
        }

        self.queries[src_ip].append(entry)

        if response_bytes is not None and response_bytes > 0:
            self.responses[src_ip].append({
                "timestamp": timestamp,
                "response_bytes": response_bytes,
            })

        self._expire(src_ip, timestamp)

    def add_response(
        self,
        timestamp: float,
        src_ip: str,
        response_bytes: int,
    ):
        """
        Record observed DNS response metadata for a client IP.
        """
        if response_bytes > 0:
            self.responses[src_ip].append({
                "timestamp": timestamp,
                "response_bytes": response_bytes,
            })
            self._expire(src_ip, timestamp)

    def _expire(self, src_ip: str, current_timestamp: float):
        """
        Remove observations older than the rolling window duration.
        """
        cutoff = current_timestamp - self.window_seconds

        query_entries = self.queries[src_ip]
        while query_entries and query_entries[0]["timestamp"] < cutoff:
            query_entries.popleft()

        resp_entries = self.responses[src_ip]
        while resp_entries and resp_entries[0]["timestamp"] < cutoff:
            resp_entries.popleft()

    def get_features(self, current_timestamp: float) -> Dict[str, Dict]:
        """
        Calculate DNS behavioral features for every active source.
        """
        # Purge expired sources
        for src_ip in list(self.queries.keys()):
            self._expire(src_ip, current_timestamp)
            if not self.queries[src_ip] and not self.responses[src_ip]:
                del self.queries[src_ip]
                if src_ip in self.responses:
                    del self.responses[src_ip]

        results = {}

        for src_ip, entries in self.queries.items():
            count = len(entries)
            if count == 0:
                continue

            domains = [e["domain"] for e in entries]
            entropies = [e["entropy"] for e in entries]
            lengths = [e["length"] for e in entries]
            max_label_lens = [e["max_label_length"] for e in entries]
            mean_label_lens = [e["mean_label_length"] for e in entries]
            ngrams = [e["ngram_anomaly"] for e in entries]
            lexicals = [e["lexical_anomaly"] for e in entries]
            qtypes = [e["qtype"] for e in entries]

            unique_domains = len(set(domains))
            mean_entropy = sum(entropies) / count
            max_entropy = max(entropies)
            mean_length = sum(lengths) / count
            max_length = max(lengths)

            high_entropy_count = sum(1 for e in entropies if e >= HIGH_ENTROPY_THRESHOLD)
            high_entropy_ratio = high_entropy_count / count

            # Advanced N-Gram & Lexical metrics
            mean_ngram = sum(ngrams) / count
            high_ngram_count = sum(1 for n in ngrams if n >= 0.40)
            high_ngram_ratio = high_ngram_count / count

            mean_lexical = sum(lexicals) / count
            lexical_count = sum(1 for l in lexicals if l >= 0.40)
            lexical_ratio = lexical_count / count

            # Label Lengths (DNS Tunnelling Chunking)
            mean_label_len = sum(mean_label_lens) / count
            max_label_len = max(max_label_lens)
            long_label_count = sum(1 for l in max_label_lens if l >= 30)
            long_label_ratio = long_label_count / count

            # Query Type Distribution
            qtype_counts = defaultdict(int)
            for qt in qtypes:
                qtype_counts[qt] += 1

            txt_count = qtype_counts.get("TXT", 0)
            txt_ratio = txt_count / count

            # Query type entropy
            qtype_entropy = 0.0
            for c in qtype_counts.values():
                p = c / count
                qtype_entropy -= p * math.log2(p)

            # Response Size Metadata
            resp_entries = self.responses.get(src_ip, [])
            if resp_entries:
                resp_sizes = [r["response_bytes"] for r in resp_entries]
                mean_response_bytes = sum(resp_sizes) / len(resp_sizes)
                max_response_bytes = max(resp_sizes)
                response_count = len(resp_sizes)
            else:
                mean_response_bytes = 0.0
                max_response_bytes = 0
                response_count = 0

            results[src_ip] = {
                # Existing Features (Preserved 100%)
                "dns_query_count": count,
                "dns_queries_per_second": count / self.window_seconds,
                "dns_unique_domains": unique_domains,
                "dns_mean_entropy": mean_entropy,
                "dns_max_entropy": max_entropy,
                "dns_mean_length": mean_length,
                "dns_max_length": max_length,
                "dns_high_entropy_ratio": high_entropy_ratio,

                # Advanced N-gram & Lexical Features
                "dns_mean_ngram_anomaly": mean_ngram,
                "dns_high_ngram_ratio": high_ngram_ratio,
                "dns_mean_lexical_score": mean_lexical,
                "dns_lexical_anomaly_ratio": lexical_ratio,

                # Label Length Features (Tunnelling Detection)
                "dns_mean_label_length": mean_label_len,
                "dns_max_label_length": max_label_len,
                "dns_long_label_ratio": long_label_ratio,

                # Query Type Distribution Features
                "dns_txt_query_count": txt_count,
                "dns_txt_query_ratio": txt_ratio,
                "dns_query_type_counts": dict(qtype_counts),
                "dns_query_type_entropy": qtype_entropy,

                # Response Metadata (Where Captured)
                "dns_mean_response_bytes": mean_response_bytes,
                "dns_max_response_bytes": max_response_bytes,
                "dns_response_count": response_count,
            }

        return results

    def reset(self):
        """Clear all stored queries and responses."""
        self.queries.clear()
        self.responses.clear()
