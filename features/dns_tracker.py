"""
CTD — DNS Query Tracker

Tracks DNS queries made by each source IP over a rolling
window, and calculates simple statistics used to spot:

  - DGA (Domain Generation Algorithm) domains: malware
    that generates lots of random-looking domain names.
  - DNS tunnelling: hiding data inside DNS queries.

Only the DOMAIN NAME TEXT (which DNS queries always send
in the clear, by design) and simple counts are used here.
"""

import math
from collections import defaultdict, deque


def calculate_entropy(text: str) -> float:
    """
    Shannon entropy of a string, in bits per character.

    Simple meaning: how "random-looking" the text is.
    Real words like "google" score LOW.
    Random strings like "xk29fpqz" score HIGH.
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


# A domain name entropy above this is considered
# "random-looking" rather than a real word/brand name.
HIGH_ENTROPY_THRESHOLD = 3.5


class DNSTracker:

    def __init__(self, window_seconds: float = 30.0):

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than 0"
            )

        self.window_seconds = window_seconds

        # src_ip -> deque of (timestamp, domain, entropy, length)
        self.queries = defaultdict(deque)

    def add_query(
        self,
        timestamp: float,
        src_ip: str,
        domain: str
    ):

        domain = domain.rstrip(".")

        entropy = calculate_entropy(domain.replace(".", ""))
        length = len(domain)

        entry = (timestamp, domain, entropy, length)

        self.queries[src_ip].append(entry)

        self._expire(src_ip, timestamp)

    def _expire(self, src_ip, current_timestamp: float):

        cutoff = current_timestamp - self.window_seconds

        entries = self.queries[src_ip]

        while entries and entries[0][0] < cutoff:
            entries.popleft()

    def get_features(self, current_timestamp: float):

        for src_ip in list(self.queries.keys()):

            self._expire(src_ip, current_timestamp)

            if not self.queries[src_ip]:
                del self.queries[src_ip]

        results = {}

        for src_ip, entries in self.queries.items():

            count = len(entries)

            if count == 0:
                continue

            domains = [entry[1] for entry in entries]
            entropies = [entry[2] for entry in entries]
            lengths = [entry[3] for entry in entries]

            unique_domains = len(set(domains))

            mean_entropy = sum(entropies) / count
            max_entropy = max(entropies)

            mean_length = sum(lengths) / count
            max_length = max(lengths)

            high_entropy_count = sum(
                1 for e in entropies
                if e >= HIGH_ENTROPY_THRESHOLD
            )

            high_entropy_ratio = high_entropy_count / count

            results[src_ip] = {
                "dns_query_count": count,
                "dns_queries_per_second": (
                    count / self.window_seconds
                ),
                "dns_unique_domains": unique_domains,
                "dns_mean_entropy": mean_entropy,
                "dns_max_entropy": max_entropy,
                "dns_mean_length": mean_length,
                "dns_max_length": max_length,
                "dns_high_entropy_ratio": high_entropy_ratio,
            }

        return results

    def reset(self):
        self.queries.clear()
