# SentinelFlow-CTD — Model, Features & Training Documentation

This document satisfies the "Expected Solution" requirement:
*"Accompanying documentation of the model(s) used, features
engineered, and the training/validation approach."*

---

## 1. Overview of the detection strategy

This system uses **two complementary detection layers**, not
just one:

1. **Rule-based detectors** (5 of them) — simple, fixed,
   explainable thresholds on engineered features. Each one
   targets exactly one of the required threat types.
2. **An unsupervised ML anomaly layer** (Isolation Forest) —
   looks at ALL engineered features together, and flags
   sources whose *overall* combination of behavior is
   statistically unusual, even if no single rule fires.

Both layers write to the same alert schema and are shown
together on the dashboard. Neither layer replaces the
other — see Section 5 for why both are kept.

---

## 2. Why rule-based detectors for 5 of the 6 threats

| Threat | Detector | Why rule-based is appropriate here |
|---|---|---|
| Reconnaissance / port scanning | `scan_detector.py` | Fan-out across ports/hosts has a precise, well-understood signature. A fixed threshold is fast, exact, and fully explainable in a demo. |
| Volumetric DDoS / SYN flood | `syn_flood_detector.py` | SYN rate and incomplete-handshake ratio are direct, deterministic indicators — no need for a learned model. |
| Data exfiltration | `exfiltration_detector.py` | The outbound/inbound byte ratio is a clear, literal match to what the problem statement asks for ("asymmetric flow-volume anomalies"). |
| Botnet C2 beaconing | `beacon_detector.py` | Regularity of timing (coefficient of variation of inter-arrival times) is a precise statistical test, not something that benefits from a black-box model. |
| DGA domains / DNS tunnelling | `dga_detector.py` | Domain-name entropy and length are simple, well-defined statistics with a long track record in real security tooling. |

Each of these follows the same pattern: calculate 3-4
relevant statistics -> compare each against a fixed
threshold -> combine into a score -> map score to
severity/confidence -> attach human-readable evidence
(the exact reasons list saved with each alert).

---

## 3. TLS metadata detector — design notes and limitation

`tls_detector.py` detects malware hidden inside encrypted
sessions using **only** TLS ClientHello metadata (cipher
suite count, extension count, presence of SNI, and
fingerprint repetition) — the ClientHello is always sent
unencrypted by design, so this never requires decrypting
anything.

A from-scratch JA3-style fingerprint calculator
(`tls_parser.py`) was built and tested against a real
TLS ClientHello (captured from Python's own `ssl` library)
to confirm correct parsing of cipher suites, extensions,
elliptic curves, and SNI.

**Honest limitation:** a production system would normally
also check the JA3 hash against a threat-intelligence
blocklist of known-malicious fingerprints. Maintaining such
a blocklist is outside the scope of a self-contained student
prototype. This detector instead flags *structural*
anomalies in the ClientHello (too few ciphers/extensions,
missing SNI, identical fingerprint repeated to one
destination) — a reasonable, explainable substitute for a
first working version.

---

## 4. The ML model

**Algorithm:** Isolation Forest (`sklearn.ensemble.IsolationForest`),
unsupervised anomaly detection.

**Why this algorithm and not a supervised classifier:**
A supervised classifier needs a large *labeled* dataset of
real attacks to learn from — building or sourcing one is a
significant project on its own. Isolation Forest instead
only needs examples of *normal* traffic: it works by
randomly partitioning the data and observing that unusual
points get isolated into their own tiny partition much
faster than normal points do. This matches this project's
real situation: we know roughly what normal traffic looks
like; a labeled dataset covering every attack variant is
much harder to obtain for a first prototype.

**Features used (16 total):** see `inference/feature_schema.py`
for the exact list and default ("no signal / normal")
values used when a feature isn't available for a given
source in a given window.

**Training approach — IMPORTANT HONESTY NOTE:**
The current training data (`inference/train_model.py`,
`generate_synthetic_normal_data()`) is **synthetic** —
reasonable made-up numbers shaped like normal traffic, not
real captured traffic from your own network. This is a
clearly-labeled placeholder so the ML layer is functional
and demonstrable immediately.

**Before a final submission**, replace the synthetic data
with a baseline built from your own recorded normal
traffic:
1. Run the packet collector during ordinary, attack-free
   usage for a while (e.g. an hour of normal browsing).
2. Save the resulting combined feature vectors (one row per
   source per window) to a CSV.
3. Load that CSV in `train_model.py` instead of calling
   `generate_synthetic_normal_data()`.
4. Re-run training and re-check the sanity-check output.

**Validation approach:** replay labeled attack traffic (for
example, from a public dataset such as CIC-IDS2017, or your
own generated attack traffic from a lab VM) through the
collector, and confirm the detectors' output aligns with the
known ground truth. Record precision/recall per threat type
if you have time before submission — this is a recommended
next step, not yet completed in this version.

**Tested limitation, discovered during development:** a
single wildly-extreme feature does not always get flagged
strongly by the ML layer alone if the other features in the
same vector look typical — a known characteristic of how
Isolation Forest randomly selects features to split on. This
is exactly why the ML layer complements, rather than
replaces, the 5 rule-based detectors, which catch precise
single/few-feature attack signatures reliably and
deterministically.

---

## 5. Why keep both layers?

| | Rule-based detectors | ML anomaly layer |
|---|---|---|
| Explainability | Very high — exact thresholds | Medium — top deviating features shown, but the model itself is a black box |
| Catches known, precise patterns | Yes, reliably | Sometimes, not guaranteed |
| Catches unusual combinations spread across many features | No | Yes |
| Needs training data | No | Yes (currently synthetic — see above) |
| Demo-friendly ("why was this flagged?") | Very demo-friendly | Demo-friendly with the z-score explanation feature |

Running both means a source can be caught either because it
matches a known, precise pattern, OR because its overall
behavior looks statistically unusual — without either layer
needing to be perfect on its own.

---

## 6. Alert schema

Every alert (from either layer) is stored with:

| Field | Meaning |
|---|---|
| `alert_id` | Unique ID |
| `source_ip` | Which device/source triggered this |
| `attack_type` | One of: `PORT_SCAN`, `SYN_FLOOD`, `DATA_EXFILTRATION`, `C2_BEACONING`, `DGA_DNS_TUNNELLING`, `TLS_METADATA_ANOMALY`, `ML_ANOMALY` |
| `severity` | `LOW` / `MEDIUM` / `HIGH` |
| `confidence` | 0.0 - 1.0 |
| `reasons` | Human-readable supporting evidence (the specific features/values that triggered the alert) |
| `timestamp` | When first observed |
| `status` | `ACTIVE` or `RESOLVED` |
| `event_count` | How many times this same alert has re-fired |

This matches the problem statement's required schema:
*"timestamp, flow identifier, threat class, confidence
score, and supporting evidence feature."*

---

## 7. Throughput target — fill this in before submission

The problem statement requires stating and demonstrating
the traffic rate the system was tested against. This has
**not yet been measured on real traffic** as part of this
documentation — you'll need to measure and record it
yourself once you run the live collector, since it depends
on your actual machine and network conditions.

**How to measure it simply:**
1. Run the collector (`python -m collector.packet_collector`)
   during a period of known traffic (e.g. run a large file
   download, or replay a PCAP file at a known rate).
2. Count how many `[FLOW]` lines are printed over a fixed
   time period (e.g. 60 seconds) to get flows/sec.
3. Sum the `bytes` field from the `[WINDOW COMPLETE]`
   sections over the same period, divide by time, to get a
   sustained Mbps figure.
4. Record both numbers here, e.g.:
   *"Tested and sustained at approximately ___ flows/sec /
   ___ Mbps on a [describe: VM / laptop / interface] setup,
   for a continuous ___ minute run without dropped packets."*

---

## 8. Architectural constraints — how this system satisfies them

| Constraint | How it's satisfied |
|---|---|
| Read-only ingest | `sniff()` only ever reads packets; no code anywhere sends packets, probes, or replies |
| No payload decryption | TLS is analyzed via `tls_parser.py`, which only reads the always-unencrypted ClientHello handshake message, never decrypted application data |
| Streaming, not batch | Detection runs every 1-second window as traffic arrives, not at the end of a capture |
| Defined throughput target | See Section 7 — measure and fill in before submission |
| Standardized alert schema | See Section 6 |
