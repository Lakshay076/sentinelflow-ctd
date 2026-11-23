# SentinelFlow-CTD: Developer Learning Guide

## 1. Introduction & Recommended Learning Roadmap

Welcome to the development team! **SentinelFlow-CTD (MONI)** is an advanced network security engine combining low-level packet dissection, streaming feature engineering, statistical heuristics, unsupervised machine learning, and full-stack web development.

To master this codebase efficiently without feeling overwhelmed, follow this structured 5-stage learning roadmap:

```
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: Fundamental Concepts & Scapy Packet Anatomy        │
│ Understand 5-tuples, TCP handshakes, and packet layers      │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ Stage 2: Flow Engine & Sliding Observation Windows          │
│ Study flow_engine.py, WindowManager, and SourceAggregator   │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ Stage 3: Deterministic Threat Detectors & Parsers           │
│ Learn the 6 rule detectors, Shannon entropy, and JA3 TLS    │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ Stage 4: Machine Learning & Incident Correlation            │
│ Isolation Forest anomaly detection and IncidentCorrelator   │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ Stage 5: Full-Stack Integration & Benchmarking              │
│ FastAPI routes, PostgreSQL/SQLite fallback, and React 19 UI │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Core Concepts Explained Simply

### 1. What is a Network 5-Tuple?
In IP networking, a communication session between two machines is uniquely identified by five values:
1. **Source IP:** Who sent the packet (e.g., `192.168.1.10`)
2. **Destination IP:** Who receives the packet (e.g., `104.244.42.1`)
3. **Source Port:** The ephemeral port on the client (e.g., `51234`)
4. **Destination Port:** The service port on the server (e.g., `443` for HTTPS, `53` for DNS)
5. **Protocol:** Transport layer protocol (`TCP`, `UDP`, or `ICMP`)

In [flow/flow_engine.py](file:///d:/Projects/sentinelflow-ctd/flow/flow_engine.py), SentinelFlow-CTD sorts these endpoints so that packets traveling in both directions belong to the same bidirectional flow:
$$\text{flow\_id} = \text{Client:51234} \leftrightarrow \text{Server:443/TCP}$$

### 2. How Does Passive Handshake Tracking Infer Client vs. Server?
Because SentinelFlow-CTD does not initiate connections, it inspects the **TCP 3-Way Handshake**:
- Packet 1: `Client -> Server` with **SYN** flag only (`S`). The sender is marked as `initiator_ip`.
- Packet 2: `Server -> Client` with **SYN + ACK** flags (`SA`). The sender is marked as `responder_ip`.
This allows the engine to know who attacked whom without relying on arbitrary port numbers.

### 3. What is Shannon Entropy and Why Does It Spot DGA Domains?
**Shannon entropy** measures the information density and "randomness" of a text string:
$$H = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- Legitimate domain names (e.g. `google.com`, `wikipedia.org`) use human-readable words with repeated vowels and common syllables $\implies$ **Low Entropy ($H < 3.0$)**.
- Malware generated via Domain Generation Algorithms (e.g. `x8k29fpqzm4a1.biz`) or DNS tunneling (encoding stolen binary data in the hostname) consists of pseudo-random character distributions $\implies$ **High Entropy ($H \ge 3.5$)**.

### 4. What is the Coefficient of Variation ($CV$) and Why Does It Spot C2 Beacons?
When a compromised host communicates with a Command-and-Control (C2) server, malware scripts check in at regular, programmed intervals (e.g., exactly every 60 seconds). Human web browsing, by contrast, is irregular.

The **Coefficient of Variation** measures relative timing variability:
$$CV = \frac{\sigma}{\mu} = \frac{\text{Standard Deviation of Intervals}}{\text{Mean Interval}}$$
- Human browsing: Highly variable intervals $\implies CV \gg 0.5$.
- Botnet check-in: Clockwork timing with near-zero variance $\implies CV \le 0.25$.

### 5. How Does JA3 Fingerprint TLS Malware Without Decryption?
When a browser or malware initiates an encrypted TLS connection, it sends an unencrypted `ClientHello` packet offering its supported cryptographic capabilities.

The **JA3 algorithm** concatenates five cleartext parameters:
$$\text{SSLVersion},\text{CipherSuites},\text{Extensions},\text{EllipticCurves},\text{PointFormats}$$
It removes dummy GREASE values and generates an MD5 hash. A Python script or Cobalt Strike beacon will offer a different, narrower set of ciphers and extensions than Google Chrome, allowing SentinelFlow-CTD to flag malware masquerading over port 443 without decrypting user data.

### 6. How Does Isolation Forest Detect Outliers?
Traditional clustering requires calculating distances across all points. **Isolation Forest** works on a fundamental insight: **anomalies are few and different**.
1. The algorithm builds an ensemble of random decision trees.
2. At each node, it picks a random feature and splits at a random value.
3. Normal points cluster tightly and take many random splits to isolate.
4. Anomalous points sit far away in the feature space and are isolated near the root of the tree in very few splits.
5. Shorter average tree depth translates directly to a high anomaly score.

---

## 3. Recommended Code Reading Sequence

Follow this exact file reading order to build your understanding step-by-step:

| Order | File Path | What to Learn |
| :---: | :--- | :--- |
| **1** | [collector/packet_record.py](file:///d:/Projects/sentinelflow-ctd/collector/packet_record.py) | Start here. Learn the basic data model holding sanitized packet metadata. |
| **2** | [flow/flow_engine.py](file:///d:/Projects/sentinelflow-ctd/flow/flow_engine.py) | Understand bidirectional flow normalization and TCP handshake role inference. |
| **3** | [features/window.py](file:///d:/Projects/sentinelflow-ctd/features/window.py) | Understand the 1.0-second time clock that drives the entire streaming pipeline. |
| **4** | [features/source_aggregation.py](file:///d:/Projects/sentinelflow-ctd/features/source_aggregation.py) | See how metrics are aggregated per source IP within a single window. |
| **5** | [detectors/scan_detector.py](file:///d:/Projects/sentinelflow-ctd/detectors/scan_detector.py) | Read your first heuristic detector. Note the threshold scoring and confidence calculation. |
| **6** | [features/beacon_tracker.py](file:///d:/Projects/sentinelflow-ctd/features/beacon_tracker.py) & [detectors/beacon_detector.py](file:///d:/Projects/sentinelflow-ctd/detectors/beacon_detector.py) | Study inter-arrival timing and the Coefficient of Variation ($CV$) calculation. |
| **7** | [features/dns_tracker.py](file:///d:/Projects/sentinelflow-ctd/features/dns_tracker.py) & [detectors/dga_detector.py](file:///d:/Projects/sentinelflow-ctd/detectors/dga_detector.py) | Study Shannon entropy calculations on domain strings. |
| **8** | [features/tls_parser.py](file:///d:/Projects/sentinelflow-ctd/features/tls_parser.py) & [detectors/tls_detector.py](file:///d:/Projects/sentinelflow-ctd/detectors/tls_detector.py) | See how binary TLS records are parsed from raw bytes without third-party libraries. |
| **9** | [inference/feature_schema.py](file:///d:/Projects/sentinelflow-ctd/inference/feature_schema.py) & [inference/ml_detector.py](file:///d:/Projects/sentinelflow-ctd/inference/ml_detector.py) | Learn how 16 streaming features are scored by the Isolation Forest model. |
| **10** | [detectors/incident_correlator.py](file:///d:/Projects/sentinelflow-ctd/detectors/incident_correlator.py) | Study how raw detector results are correlated, collapsed, and attributed to victims. |
| **11** | [alerts/alert_manager.py](file:///d:/Projects/sentinelflow-ctd/alerts/alert_manager.py) & [alerts/alert_store.py](file:///d:/Projects/sentinelflow-ctd/alerts/alert_store.py) | Learn incident deduplication, stale resolution, and PostgreSQL/SQLite persistence. |
| **12** | [collector/pcap_replay_collector.py](file:///d:/Projects/sentinelflow-ctd/collector/pcap_replay_collector.py) | Understand time-shifting and maximum-speed throughput benchmarking. |
| **13** | [api/main.py](file:///d:/Projects/sentinelflow-ctd/api/main.py) & [api/routes/](file:///d:/Projects/sentinelflow-ctd/api/routes) | Learn the FastAPI route controllers. |
| **14** | [frontend/src/App.jsx](file:///d:/Projects/sentinelflow-ctd/frontend/src/App.jsx) | Explore the React polling state and UI component structure. |

---

## 4. Hands-On Developer Exercises

Put theory into practice by completing these four developer exercises:

### Exercise 1: Replay Traffic & Measure Throughput
**Goal:** Run a PCAP replay at maximum speed and inspect the throughput benchmark output.
```bash
# 1. Generate a synthetic gateway capture with attacks:
python scripts/generate_synthetic_traffic.py --out lab_test.pcap

# 2. Replay at max speed:
python -m collector.pcap_replay_collector lab_test.pcap --max-speed

# 3. Score the detection results against ground truth:
python scripts/validate_detections.py lab_test.pcap.ground_truth.json
```
*Question to Answer:* What was the sustained packet rate (pps) and Mbps achieved by your machine?

---

### Exercise 2: Trigger an Attack Simulation via API
**Goal:** Simulate an attack using curl and verify that it appears in the active alerts list.
```bash
# 1. Start the API server in one terminal:
uvicorn api.main:app --reload --port 8000

# 2. In another terminal, trigger a SYN flood simulation:
curl -X POST http://localhost:8000/api/alerts/simulate/SYN_FLOOD

# 3. Query active alerts:
curl http://localhost:8000/api/alerts/active
```
*Question to Answer:* Inspect the JSON response. What are the specific reasons listed in the alert?

---

### Exercise 3: Inspect the TLS JA3 Parser
**Goal:** Run a standalone Python snippet to parse a mock TLS ClientHello and compute its JA3 hash.
```python
from features.tls_parser import parse_client_hello, compute_ja3

# Sample minimal TLS 1.2 ClientHello byte sequence
mock_hello = bytes.fromhex(
    "1603010034010000300303" + "00"*32 + "00" + "0004c02bc02f" + "010000050000000000"
)

parsed = parse_client_hello(mock_hello)
if parsed:
    ja3_str, ja3_hash = compute_ja3(parsed)
    print("JA3 String:", ja3_str)
    print("JA3 Hash:  ", ja3_hash)
```

---

### Exercise 4: Retrain the Machine Learning Model
**Goal:** Train the Isolation Forest model on a clean benign traffic baseline.
```bash
# 1. Generate a capture containing ONLY benign browsing:
python scripts/generate_synthetic_traffic.py --out benign_lab.pcap --attacks

# 2. Fit the model using the live feature extraction pipeline:
python -m inference.train_model_from_pcap benign_lab.pcap --contamination 0.02
```
*Verify:* Check that `inference/model.joblib` and `inference/feature_stats.json` were updated with fresh timestamps.

---

## 5. Common Errors, Solutions & Debugging Tips

### 1. "No trained model found yet" Warning
- **Cause:** `inference/model.joblib` or `inference/feature_stats.json` does not exist.
- **Fix:** The engine will continue running rule-based detectors safely. To enable the ML layer, run `python -m inference.train_model_from_pcap benign.pcap`.

### 2. High Packet Loss During Live Capture
- **Cause:** Scapy is written in pure Python; under gigabit loads ($> 50,000\text{ pps}$), the Python GIL and user-space packet copying will cause kernel buffer drops.
- **Fix:** For enterprise live sniffing, production deployments use C-based capture daemons (e.g. `AF_PACKET` with `mmap` or DPDK) spooling PCAP chunks to disk, then read via SentinelFlow's `--watch` directory mode (`pcap_replay_collector.py --watch /path/to/spool`).

### 3. Resetting All State for a Clean Test
If you want to clear out old test alerts and start fresh:
```bash
python -c "from alerts.alert_store import AlertStore; AlertStore().clear_all()"
python -c "from telemetry.live_metrics import live_metrics; live_metrics.clear()"
```
