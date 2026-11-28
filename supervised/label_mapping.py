"""
SentinelFlow-CTD — Supervised Classifier: Label Mapping
========================================================

Maps the original CIC-IDS2017 dataset labels to the SentinelFlow
threat categories defined in the project specification.

Design decisions
----------------
- Mapping is defined explicitly here as a plain dict. Any label found in the
  dataset that is NOT in this dict will be flagged as UNMAPPED rather than
  silently dropped.
- Original labels are preserved in the processed dataset for traceability.
- A special UNKNOWN category is reserved for runtime low-confidence predictions;
  it is NOT a training label (no samples in the dataset map to it).

Threat categories
-----------------
  BENIGN          Normal background traffic.
  DOS_DDOS        Denial-of-service and distributed DoS attacks, including
                  volumetric floods and application-layer slow attacks.
  RECONNAISSANCE  Network scanning and port-scanning activity.
  BRUTE_FORCE     Credential brute-force (FTP-Patator, SSH-Patator).
  WEB_ATTACK      HTTP-layer attacks (SQLi, XSS, brute-force login).
  BOTNET_C2       Botnet command-and-control beaconing.
  INFILTRATION    Post-exploitation lateral movement / infiltration activity.
  OTHER_ATTACK    Attack traffic that does not fit the above categories
                  (e.g. Heartbleed).

UNKNOWN / UNCLASSIFIED is used ONLY at inference time when model confidence
is below the configured threshold. It is never a training label.
"""

from typing import Dict, Optional

# ------------------------------------------------------------------ #
# Primary label mapping                                               #
# ------------------------------------------------------------------ #
# Keys  : exact strings as they appear in the CIC-IDS2017 Label column
#         (after stripping leading/trailing whitespace).
# Values: SentinelFlow threat category strings.
# ------------------------------------------------------------------ #

LABEL_TO_CATEGORY: Dict[str, str] = {
    # ---- Benign -------------------------------------------------- #
    "BENIGN": "BENIGN",

    # ---- DoS / DDoS ---------------------------------------------- #
    "DoS Hulk":          "DOS_DDOS",
    "DDoS":              "DOS_DDOS",
    "DoS GoldenEye":     "DOS_DDOS",
    "DoS slowloris":     "DOS_DDOS",
    "DoS Slowhttptest":  "DOS_DDOS",
    "Heartbleed":        "OTHER_ATTACK",   # TLS exploit — not a flood

    # ---- Reconnaissance ------------------------------------------ #
    "PortScan": "RECONNAISSANCE",

    # ---- Brute force --------------------------------------------- #
    "FTP-Patator": "BRUTE_FORCE",
    "SSH-Patator": "BRUTE_FORCE",

    # ---- Web attacks --------------------------------------------- #
    "Web Attack \xef\xbf\xbd Brute Force":  "WEB_ATTACK",
    "Web Attack \xef\xbf\xbd XSS":          "WEB_ATTACK",
    "Web Attack \xef\xbf\xbd Sql Injection": "WEB_ATTACK",
    # Replacement-character variants (pandas reads mojibake as U+FFFD)
    "Web Attack \ufffd Brute Force":  "WEB_ATTACK",
    "Web Attack \ufffd XSS":          "WEB_ATTACK",
    "Web Attack \ufffd Sql Injection": "WEB_ATTACK",
    # ASCII-fallback variant (some tools strip non-ASCII entirely)
    "Web Attack  Brute Force":  "WEB_ATTACK",
    "Web Attack  XSS":          "WEB_ATTACK",
    "Web Attack  Sql Injection": "WEB_ATTACK",

    # ---- Botnet / C2 --------------------------------------------- #
    "Bot": "BOTNET_C2",

    # ---- Infiltration / lateral movement ------------------------- #
    "Infiltration": "INFILTRATION",
}

# Ordered list of categories (excluding runtime-only UNKNOWN).
# Used as the canonical class order for the label encoder.
ORDERED_CATEGORIES = [
    "BENIGN",
    "DOS_DDOS",
    "RECONNAISSANCE",
    "BRUTE_FORCE",
    "WEB_ATTACK",
    "BOTNET_C2",
    "INFILTRATION",
    "OTHER_ATTACK",
]

# Runtime-only prediction value for low-confidence outputs.
# NEVER appears as a training label.
UNKNOWN_CATEGORY = "UNCLASSIFIED"

# Confidence threshold below which a prediction becomes UNCLASSIFIED.
# Can be overridden at inference time.
DEFAULT_CONFIDENCE_THRESHOLD = 0.50


def map_label(raw_label: str) -> Optional[str]:
    """
    Map one raw CIC-IDS2017 label string to a SentinelFlow category.

    Returns None if the label is not in the mapping (caller must handle
    unmapped labels explicitly — do not silently drop them).
    """
    if raw_label is None:
        return None
    cleaned = str(raw_label).strip()
    return LABEL_TO_CATEGORY.get(cleaned)


def map_labels_series(series):
    """
    Vectorised mapping of a pandas Series of raw labels.

    Returns a tuple (mapped_series, unmapped_mask) where:
      - mapped_series  : Series with mapped category strings (None for unmapped)
      - unmapped_mask  : boolean Series (True where label could not be mapped)
    """
    mapped = series.str.strip().map(LABEL_TO_CATEGORY)
    unmapped_mask = mapped.isna()
    return mapped, unmapped_mask


def build_mapping_report(label_counts: Dict[str, int]) -> Dict:
    """
    Build a human-readable mapping report given a dict of
    {raw_label: record_count} from the dataset.

    Returns a dict with:
      - original_labels   : list of {label, count, mapped_to}
      - category_totals   : {category: total_count}
      - unmapped_labels   : list of {label, count} that could not be mapped
      - total_records     : int
      - total_unmapped    : int
    """
    original_labels = []
    category_totals: Dict[str, int] = {}
    unmapped_labels = []
    total_records = 0
    total_unmapped = 0

    for raw_label, count in sorted(label_counts.items(), key=lambda x: -x[1]):
        total_records += count
        mapped = map_label(raw_label)

        if mapped is not None:
            original_labels.append({
                "label": raw_label,
                "count": count,
                "mapped_to": mapped,
            })
            category_totals[mapped] = category_totals.get(mapped, 0) + count
        else:
            original_labels.append({
                "label": raw_label,
                "count": count,
                "mapped_to": None,
            })
            unmapped_labels.append({"label": raw_label, "count": count})
            total_unmapped += count

    return {
        "original_labels": original_labels,
        "category_totals": category_totals,
        "unmapped_labels": unmapped_labels,
        "total_records": total_records,
        "total_unmapped": total_unmapped,
    }
