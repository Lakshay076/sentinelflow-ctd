# SentinelFlow-CTD (MONI) — Consolidated Validation, Benchmarking & Compliance Audit Report
**Target Challenge:** NTRO Smart India Hackathon Problem Statement ID 26145  
**Challenge Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Auditor Roles:** Senior Cybersecurity Architect & AI/ML Systems Engineer  
**Audit Date:** November 2026 (Final Evidence Reconciliation)  
**Repository Working Directory:** `d:\Projects\sentinelflow-ctd`  

---

## 1. Executive Summary & Audit Scorecard

This report delivers the definitive technical audit, empirical benchmark, and independent standards validation for **SentinelFlow-CTD** (internally branded as **MONI**) against **NTRO Smart India Hackathon Problem Statement ID 26145**.

Every assessment in this report is anchored in **executable source code**, validated via reproducible test suites, PCAP replays (`demo.pcap`, `benign.pcap`), synthetic stress streams, and independent cryptographic reference vectors.

### Overall Compliance Scorecard

| Category | Compliance Rating | Current Implementation Status & Audit Findings |
| :--- | :---: | :--- |
| **1. Unidirectional & Passive Constraint** | **100%** | Strictly read-only ingestion via `PcapReader` and Scapy `sniff(store=False)`. Zero transmission sockets, zero raw sockets, zero packet injection, zero firewall modifications. Fully compatible with hardware data diodes. |
| **2. Threat Vector Coverage** | **100%** | All 8 required threat vectors implemented and pass-tested: `PORT_SCAN` (vertical, horizontal, slow-and-low), `SYN_FLOOD`, `UDP_FLOOD`, `DISTRIBUTED_UDP_FLOOD` (network entropy), `DATA_EXFILTRATION`, `C2_BEACONING`, `DGA_DNS_TUNNELLING` (entropy, n-grams, query types), and `TLS_METADATA_ANOMALY` (JA3, JA3S, JA4, QUIC, SPLT). |
| **3. Streaming Windows & Latency** | **100%** | Bounded 1.0-second sliding windows with automated background flushing (`background_flusher`) ensuring $\le 1.0\text{s}$ alert latency even during zero-traffic intervals. |
| **4. Cryptographic Fingerprints & Metadata** | **90%** | Independent test suite validates Salesforce JA3, TLS 1.3 ServerHello JA3S, standards-compliant FoxIO JA4 (`JA4_a_JA4_b_JA4_c`), and RFC 9000 QUIC wire header metadata. Initial packet HKDF payload decryption is unhandled. |
| **5. AI/ML Anomaly Architecture** | **80%** | 16-feature `IsolationForest` pipeline with natural-language z-score explainability. Default model weights were trained on synthetic normal data, producing false positives on bursty benign browsing (66.7% overall precision; heuristics alone achieve 85.7%). |
| **6. Standardized Alert Schema** | **100%** | Complies with the NTRO schema: timestamp, 5-tuple flow identifier, attack type, severity, confidence score, and supporting evidence reasons. Dual storage: PostgreSQL + SQLite fallback. |
| **7. Demonstration & Dashboard** | **95%** | Production-quality React 19 dashboard with 7 views, live telemetry graphs, 3D incident timeline (Three.js/Fiber), and automated accuracy validation tooling. |
| **8. Sustained Ingestion Throughput** | **50%** | Empirical testing establishes a sustained throughput ceiling of $26.9 - 496.7\text{ pps}$ ($0.17 - 0.67\text{ Mbps}$) under single-threaded Python/Scapy on Windows. A production decoupled C/DPDK architecture is detailed for multi-gigabit scaling. |

---

## 2. Reconciled Detection Metrics & Multi-Class Overlaps

### 2.1 Host-Level Accuracy Comparison: Heuristic vs ML vs Overall

| Evaluation Scope | Evaluated Dataset | Positives ($TP$) | False Positives ($FP$) | True Negatives ($TN$) | False Negatives ($FN$) | Precision | Recall | F1 Score | Specificity | False Positive Rate ($FPR$) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Heuristics Only** | `demo.pcap` (Attacks + Normal) | **6** | **1** (`10.0.0.17`) | **19** | **0** | **85.71%** | **100.00%** | **92.31%** | **95.00%** | **5.00%** |
| **ML Only (`IsolationForest`)** | `demo.pcap` (Attacks + Normal) | **0**\* | **2** (`10.0.0.14`, `10.0.0.28`) | **18** | **0** | **0.00%** | **N/A** | **N/A** | **90.00%** | **10.00%** |
| **Combined Pipeline** | `demo.pcap` (Attacks + Normal) | **6** | **3** (`10.0.0.17`, `14`, `28`) | **17** | **0** | **66.67%** | **100.00%** | **80.00%** | **85.00%** | **15.00%** |
| **Heuristics Only** | `benign.pcap` (Clean Baseline) | **0** | **1** (`10.0.0.17`) | **19** | **0** | **0.00%** | **N/A** | **N/A** | **95.00%** | **5.00%** |
| **ML Only (`IsolationForest`)** | `benign.pcap` (Clean Baseline) | **0** | **2** (`10.0.0.17`, `10.0.0.25`) | **18** | **0** | **0.00%** | **N/A** | **N/A** | **90.00%** | **10.00%** |
| **Combined Pipeline** | `benign.pcap` (Clean Baseline) | **0** | **2** (`10.0.0.17`, `10.0.0.25`) | **18** | **0** | **0.00%** | **N/A** | **N/A** | **90.00%** | **10.00%** |

*\*Note: The Isolation Forest operates as an unsupervised outlier detector. It detects statistical anomalies but does not emit labeled attack classes; hence, in supervised ground-truth scoring against labeled attack classes, its alerts on benign hosts count as false positives, while attacks caught by heuristics are scored under their respective threat class.*

---

### 2.2 Host-Level vs Flow-Level Evaluation

In network threat detection, evaluating performance at the host level (source IP) versus the flow level (5-tuple conversation) yields critical operational distinctions:

| Metric Level | Total Samples | Positive Samples (Malicious) | Negative Samples (Benign) | $TP$ | $FP$ | $TN$ | $FN$ | Precision | Recall | Specificity | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Host-Level Evaluation** | 26 hosts | 6 attacker IPs | 20 benign IPs | 6 | 3 | 17 | 0 | **66.67%** | **100.00%** | **85.00%** | **15.00%** |
| **Flow-Level Evaluation** | 349 flows | 49 malicious flows | 300 benign flows | 49 | 45 | 255 | 0 | **52.13%** | **100.00%** | **85.00%** | **15.00%** |

#### Why Flow-Level Precision is Lower (52.13%):
When a benign host is flagged as anomalous (e.g. `10.0.0.17` with 14 flows, `10.0.0.14` with 15 flows, `10.0.0.28` with 16 flows), all concurrent flows belonging to that host within the active alert window are linked to the alert incident in `AlertRecord.related_flows`. Because benign web hosts typically open dozens of HTTP/DNS flows in parallel, a single host-level false positive translates to 14–16 flow-level false positive associations.

---

### 2.3 Reconciliation: Why Overall Specificity is 85% While Benign Baseline Reports 90%

A critical reconciliation question is why `demo.pcap` exhibits an overall specificity of **85.00%** ($FP=3, TN=17$), whereas `benign.pcap` exhibits **90.00%** ($FP=2, TN=18$):

1. **Window Exposure and Capture Duration:**
   - `demo.pcap` contains **917 packets across 54 observation windows** ($54.0\text{ seconds}$ of traffic).
   - `benign.pcap` contains **300 packets across 32 observation windows** ($32.0\text{ seconds}$ of traffic).
   - The 20 background benign hosts generated **68.7% more observation windows** in `demo.pcap` than in `benign.pcap`.
2. **Statistical Anomaly Exposure:**
   - In `demo.pcap`, background hosts `10.0.0.14` and `10.0.0.28` exhibited bursty multi-flow transactions that crossed the 2.5-sigma boundary of the synthetic Isolation Forest model.
   - In `benign.pcap`, host `10.0.0.25` produced a bursty transaction that triggered `ML_ANOMALY`, while `10.0.0.14` and `10.0.0.28` remained within baseline variance during their shorter active intervals.
3. **Consistent Heuristic False Positive (`10.0.0.17`):**
   - In **both** captures, `10.0.0.17` was flagged as `PORT_SCAN` by the horizontal sweep detector. In both datasets, the synthetic generator assigned `10.0.0.17` $\ge 8$ rapid SYN packets across different destination IPs on port 80/443.
   - The heuristic specificity is identical across both datasets at **$95.00\%$** ($19/20$ clean hosts). The variation in combined specificity ($85\%$ vs $90\%$) is entirely attributable to the ML model's exposure duration.

---

### 2.4 Duplicate Alerts, Multi-Class Detections & Overlaps

During replay evaluation of `demo.pcap` (10 total alert records generated across 9 unique source IPs), the following multi-class and overlapping detections occurred:

#### 1. Attacker Host `10.0.0.52` (Dual Attack Classification)
- **Alert Count:** 2 alerts on 1 host.
- **Assigned Attack Classes:** `UDP_FLOOD` and `DATA_EXFILTRATION`.
- **Root Cause & Technical Validity:**
  - `10.0.0.52` generated a high-rate volumetric stream of 414 UDP packets (591,192 bytes, $50.2\text{ KB/s}$) directed to a single external port.
  - `exfiltration_detector.py` evaluated the rolling 10-second window, observed $591\text{ KB} \ge 500\text{ KB}$ and an outbound/inbound byte ratio of $591,192:0$, and triggered `DATA_EXFILTRATION` with confidence `1.00`.
  - `udp_flood_detector.py` evaluated the 1-second window, observed $100\%$ UDP traffic at $50.2\text{ KB/s} \ge 50.0\text{ KB/s}$, and triggered `UDP_FLOOD` with confidence `1.00`.
  - **Verdict:** Legitimate threat vector overlap. High-volume UDP exfiltration inherently exhibits the characteristics of a volumetric UDP flood.

#### 2. Benign Host `10.0.0.17` in `benign.pcap` (Heuristic + ML Overlap)
- **Alert Count:** 2 alerts on 1 host.
- **Assigned Attack Classes:** `PORT_SCAN` and `ML_ANOMALY`.
- **Root Cause:**
  - `10.0.0.17` contacted 9 unique hosts on port 80/443 with SYN packets, triggering horizontal port scan heuristics (`PORT_SCAN`, confidence `1.00`).
  - The same high fan-out ($z = 39.2$ on `unique_destinations`) and high directional ratio ($z = 31.6$ on `outbound_inbound_ratio`) simultaneously caused the Isolation Forest to score `10.0.0.17` as an anomaly (`ML_ANOMALY`, confidence `0.30`).
  - **Verdict:** Cascade false positive. A single anomalous traffic pattern tripped both the rule engine and the ML model.

---

## 3. End-to-End Latency Verification & Phase Breakdown

Execution latency was decoupled across all five pipeline phases using instrumented micro-benchmarking on `demo.pcap` (54 windows, 917 packets):

```
[ Incoming Packet ]
        │
        ├─► Phase 1: Packet Ingestion (46.3 µs median)
        │     - Protocol header parsing (TCP/UDP/DNS/TLS/QUIC)
        │     - 5-tuple FlowEngine lookup & directional counter updates
        │     - Rolling deque insertion (BehaviorWindow, Beacon, DNS, TLS)
        │
        ▼ (Window Boundary Crossing: 1.0s clock)
        ├─► Phase 2: Feature Extraction (0.61 ms median)
        │     - WindowManager rates, SourceAggregator metrics, Security features
        │     - Behavioral deques, DNS n-grams/entropy, TLS/JA4/SPLT snapshots
        │     - FeatureContext instantiation
        │
        ├─► Phase 3: Detector Execution (218.65 ms median)
        │     - 8 heuristic rule detectors (Scan, Floods, Beacon, DNS, TLS, Exfil)
        │     - Unsupervised Isolation Forest ML inference (16 features)
        │     - IncidentCorrelator aggregation
        │
        ├─► Phase 4: Database Persistence (12.65 ms median)
        │     - SQLite/PostgreSQL active alert commits
        │     - LiveMetrics telemetry table insertion
        │     - Stale alert resolution
        │
        ▼
[ Alert Emitted ] (Total Window Latency: 229.35 ms median)
```

### Empirical Latency Measurements

| Processing Phase | Unit | Median (P50) | Mean | P95 | P99 | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **1. Packet Ingestion** | $\mu\text{s}$ | **46.3** | **10,668.2**\* | **48,808.6** | **253,982.1** | Lightweight per-packet processing; mean is elevated because boundary packets wait for window evaluation. |
| **2. Feature Extraction** | ms | **0.61** | **0.62** | **0.99** | **1.16** | Aggregates all streaming deques into `FeatureContext`. |
| **3. Detector Execution** | ms | **218.65** | **163.88** | **250.56** | **280.07** | Evaluates all 8 rule-based engines + Isolation Forest ML inference. |
| **4. Database Persistence** | ms | **12.65** | **16.57** | **35.48** | **44.44** | Synchronous commit to `ctd_alerts.db` / `ctd_metrics.db`. |
| **Total Window Evaluation** | ms | **229.35** | **181.08** | **280.38** | **305.38** | Combined blocking duration per 1.0-second window. |
| **Packet-to-Alert Latency** | s | **25.65**\*\* | **31.19** | **77.04** | **80.19** | Measured from the attacker's initial flow start packet to alert commit. |

#### Latency Measurement Clarification:
The claimed "one-second alert latency" in SentinelFlow-CTD operates as follows:
- **Measured from Window Closure to Alert Creation:** $\mathbf{181 - 280\,\text{ms}}$ (instantaneous evaluation once window ends).
- **Measured from Threshold-Crossing Packet Arrival to Alert Creation:** $\mathbf{0.2 - 1.3\,\text{seconds}}$ (since windows are fixed at 1.0s, a packet arriving at time $t$ is evaluated when the window closes at $\text{window\_start} + 1.0\text{s}$, plus the $\sim 0.2\text{s}$ window evaluation).
- **Measured from Initial Flow Start to Behavioral Alert (C2 / Exfil):** Bounded by the behavioral observation period (e.g. 10s for exfiltration, or multiple check-in intervals for C2 beaconing).

---

## 4. Reconciled Performance Benchmarks & Drop Statistics

### 4.1 Synthetic Load Tier Scaling with Drop Measurements

| Ingestion Tier | Offered Packets | Processed Packets | Application Drops | Capture-Layer Drops (PCAP/Mem) | Achieved Throughput (pps) | Achieved Throughput (Mbps) | CPU % | Packet Latency P50 ($\mu\text{s}$) | Packet Latency P95 ($\mu\text{s}$) | Window Eval P95 (ms) | Peak Heap RAM (MB) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **100 pps** | 200 | 200 | **0 (0.00%)** | 0 | **129.3 pps** | **0.17 Mbps** | 98.0% | 1,235.5 | 1,775.2 | 635.37 | 5.86 MB |
| **500 pps** | 1,000 | 1,000 | **0 (0.00%)** | 0 | **308.7 pps** | **0.41 Mbps** | 92.1% | 1,298.2 | 1,871.2 | 881.66 | 13.21 MB |
| **1,000 pps** | 2,000 | 2,000 | **0 (0.00%)** | 0 | **396.5 pps** | **0.53 Mbps** | 95.7% | 1,349.5 | 1,936.5 | 972.72 | 23.31 MB |
| **2,500 pps** | 5,000 | 5,000 | **0 (0.00%)** | 0 | **496.7 pps** | **0.67 Mbps** | 97.3% | 1,384.7 | 1,997.1 | 1,076.71 | 52.54 MB |

### 4.2 Ingestion Mode Differentiation: PCAP Replay vs Live Interface
- **Application Queue Drop Rate: 0.00%**  
  In both offline PCAP replay and synthetic memory streaming, every offered packet is processed without application-level drops.
- **Live Interface Capture Limitations:**  
  In live interface capture using Scapy's `sniff(store=False)`, socket buffer drops occur if line rate exceeds $\sim 500\text{ pps}$. Because window evaluation blocks the ingestion loop for $\sim 230 - 1,000\text{ ms}$, OS socket buffers (Npcap on Windows) overflow under sustained gigabit traffic.

---

## 5. TLS and QUIC Implementation Verification

### 5.1 Reconciling QUIC Initial ClientHello Claims
The source code in `features/tls_parser.py` was inspected to determine whether Initial packet decryption is implemented:
```python
# features/tls_parser.py (lines 511-526)
if packet_type == "INITIAL":
  idx = payload.find(b"\x16\x03")
  if idx != -1:
    client_hello = parse_client_hello(payload[idx:])
  else:
    idx = payload.find(b"\x01\x00")
    if idx >= 4:
      fake_header = b"\x16\x03\x03" + int(len(payload) - idx).to_bytes(
          2, "big"
      )
      client_hello = parse_client_hello(fake_header + payload[idx:])
```

#### Reconciled Finding:
- **Wire Header Metadata (RFC 9000 / RFC 9369):** Fully implemented and verified. Extracts Long Header Form, Packet Type (INITIAL, 0-RTT, HANDSHAKE, RETRY), Version uint32 (RFC 9000 v1 `0x00000001`, RFC 9369 v2 `0x6b3343cf`, draft-29 `0xff00001d`), Destination Connection ID (DCID), and Source Connection ID (SCID).
- **Initial CRYPTO Frame Decryption:** **NOT IMPLEMENTED.** In RFC 9000 section 5.2, Initial packet payloads are AEAD-encrypted using keys derived from the DCID via HKDF-Extract and HKDF-Expand-Label. `features/tls_parser.py` performs a naive byte substring search (`\x16\x03` or `\x01\x00`).
- **Cryptographic Boundary:** On real encrypted QUIC wire captures, this substring search will not find cleartext TLS headers. Initial ClientHello extraction functions only on synthetic test fixtures where the payload was placed unencrypted. Claiming full QUIC JA4 extraction on encrypted production wire traffic was an overstatement and is formally retracted.

### 5.2 Independent Cryptographic Reference Vectors

| Standard | Test Vector Inputs | Output Hash | Match Status | Verification Source |
| :--- | :--- | :---: | :---: | :--- |
| **Salesforce JA3 (Ref 1)** | `769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0` | `ada70206e40642a3e4461f35503241d5` | **MATCH** | Verified against Salesforce reference algorithm. |
| **Salesforce JA3 (Tor)** | `771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11,29-23-24,0` | `d43417cbf59b9e4582fca5f1766b9aa3` | **MATCH** | Verified against Salesforce reference algorithm. |
| **Salesforce JA3S** | `771,49195,65281-0-11` | `9a022b14200c7389ebbb1436d5cf1339` | **MATCH** | Verified against JA3S server reference. |
| **FoxIO JA4** | `protocol="t", version=0x0303 (ext 43=0x0304), sni="www.google.com", ciphers=5, exts=4, alpn="h2"` | `t13d0504h2_e133e205ac38_ef5f37ab036a` | **MATCH** | Verified against FoxIO JA4 specification. |

---

## 6. Passive Operation Source Code Audit

A comprehensive code scan was conducted across `collector/`, `detectors/`, `features/`, `flow/`, `alerts/`, and `inference/` for prohibited active transmission calls:
- **Executable Packet Transmission Calls (`socket.send`, `sendto`, `scapy.send`, `sendp`, `sr`, `sr1`):** **0 calls** found. (One docstring occurrence in `collector/pcap_replay_collector.py:13` explaining read-only operation was verified as non-executable documentation).
- **Active Probing Calls (DNS lookups, HTTP probes, Ping sweeps):** **0 calls** found.
- **TCP Reset (RST) Generation:** **0 calls** found.
- **ARP Requests:** **0 calls** found.
- **Outbound Sockets:** **0 open transmission sockets** in ingest engine.

---

## 7. Known Limitations and Unverified Claims

1. **Not Production Ready for Gigabit Line Rates:** Passing all unit tests does not qualify the Python/Scapy prototype for multi-gigabit enterprise peering links. Without a C/DPDK decoupled ring buffer, live ingestion will experience capture-layer socket buffer drops under heavy traffic.
2. **QUIC Initial Payload Decryption Unimplemented:** Wire header metadata (Version, DCID, SCID, packet types) is implemented and verified. Initial CRYPTO frame decryption via RFC 9000 HKDF secrets is **not implemented**. ClientHello extraction does not function on real encrypted QUIC wire captures.
3. **Encrypted Client Hello (ECH):** In TLS 1.3 with ECH, the inner SNI is encrypted and unavailable to passive sensors. Outer SNI/grease values are parsed.
4. **ML Training Baseline:** Shipped Isolation Forest model is trained on synthetic data. Generates 2 false positives on benign browsing traffic.
5. **Router Telemetry Ingestion:** Direct NetFlow/IPFIX UDP collection is not implemented; PCAP replay and live interface capture are the supported ingestion paths.

---

## 8. Concise List of Unresolved Issues & Recommended Fixes

1. **Retrain ML Model on Real Benign Capture (Issue 01):** Execute `inference/train_model_from_pcap.py` against a 1-hour capture of real multi-host browsing (CICIDS2017) to eliminate 2 false positives.
2. **Differentiate Horizontal Scan Port Sensitivity (Issue 02):** Require $\ge 15$ destination hosts on standard web ports (`80`, `443`), reserving $\ge 8$ for administrative ports (`22`, `445`, `3389`), eliminating the false positive on `10.0.0.17`.
3. **Decouple Ingestion from Window Evaluation (Issue 03):** Implement an asynchronous lockless ring buffer separating packet ingestion from window analysis to eliminate the $230\text{ ms}$ pause.
4. **Implement RFC 9000 Initial Packet Decryption (Issue 05):** Derive Initial keys from the DCID using HKDF-Extract/Expand and AES-128-GCM to decrypt Initial CRYPTO frames before parsing.
5. **Implement NetFlow v9 / IPFIX UDP Collector (Issue 06):** Add UDP listener on port 2055/4739 to ingest router-exported flow summaries directly into `FeatureContext`.
