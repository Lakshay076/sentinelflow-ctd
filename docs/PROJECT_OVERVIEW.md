# SentinelFlow-CTD: Project Overview & Objectives

## 1. Project Introduction & System Identity

**SentinelFlow-CTD (Cyber Threat Detection Engine)** — branded in its user interface as **MONI** — is a real-time, non-intrusive, passive network cyber threat detection and monitoring platform. It is engineered specifically for high-throughput observation environments such as perimeter gateway links, internet exchange points, and peering connections where network visibility is mandatory but operational disruption is prohibited.

The system was designed and aligned with the **Smart India Hackathon (SIH)** cybersecurity problem statement, which requires:
1. Passive, one-directional observation of simulated or live IP network traffic.
2. Ingestion of multi-host gateway traffic streams without interfering with live communications.
3. Rapid extraction of streaming network flow features into continuous observation windows.
4. Detection across a standardized taxonomy of threat vectors.
5. Standardized alert schemas containing timestamps, flow identifiers, threat classes, confidence scores, and supporting evidence.
6. Empirical demonstration of sustained throughput metrics (packets per second, Mbps, flows per second).

---

## 2. Problem Statement: Inline vs. Passive Threat Detection

### The Traditional Inline Challenge
Traditional enterprise defense systems (such as Intrusion Prevention Systems, Next-Gen Firewalls, and Web Application Firewalls) sit **in-line** with production traffic. While inline devices can block malicious packets in real time, they introduce severe architectural limitations:

1. **Latency and Throughput Bottlenecks:** Every packet must be copied into user-space, processed through complex regex trees, and reinjected onto the wire, creating microsecond-to-millisecond latency spikes and throughput limits.
2. **Single Point of Failure (SPOF):** If an inline engine crashes, runs out of memory, or experiences kernel panics under volumetric DDoS attacks, production network connectivity halts entirely.
3. **Operational False Positives:** In mission-critical environments (telecoms, hospitals, industrial control systems), accidentally dropping legitimate packets due to false-positive heuristics is unacceptable.
4. **Encryption Blindness:** With modern TLS 1.3 and forward secrecy, deep packet inspection (DPI) requires breaking encryption via Man-in-the-Middle (MitM) certificate proxies. This increases computational overhead, violates user privacy, and creates compliance liabilities.

### The SentinelFlow-CTD Passive Solution
SentinelFlow-CTD solves these challenges by functioning as a **strictly passive network sensor**, architecturally mirroring a hardware **optical TAP** or **hardware data diode**:

- **Physical One-Way Ingestion:** The engine only ever reads packets from disk captures (`PcapReader`) or listens passively on a network interface (`sniff()`). It never transmits packets, initiates handshakes, or alters routing tables.
- **Payload-Agnostic Metadata Inspection:** Traffic is analyzed strictly through network metadata: packet headers, byte volumes, directional ratios, TCP handshake timing, DNS query text, and cleartext TLS `ClientHello` structures. It does not attempt to decrypt application data.
- **Fail-Safe Operation:** Because it operates on a passive mirror copy, even complete failure or termination of the detection engine has zero effect on production network availability.

---

## 3. Major Features & Capabilities

SentinelFlow-CTD provides an end-to-end detection pipeline covering seven distinct threat vectors:

### Core Threat Coverage

| Threat Class | Identifier | Detection Mechanism | Primary Code Reference |
| :--- | :--- | :--- | :--- |
| **Port Scanning / Reconnaissance** | `PORT_SCAN` | Detects rapid fan-out across multiple destination ports and IPs, accompanied by high TCP SYN ratios and connection rates. | `detectors/scan_detector.py` |
| **Volumetric DDoS / SYN Flood** | `SYN_FLOOD` | Identifies surges of incomplete TCP handshakes, tracking elevated SYN packet ratios ($\ge 80\%$) and high SYN creation rates ($\ge 50\text{ SYN/s}$). | `detectors/syn_flood_detector.py` |
| **Volumetric UDP Flood & Reflection** | `UDP_FLOOD` | Detects high-rate UDP surges, port saturation, and known reflection service vectors (DNS 53, NTP 123, SSDP 1900, Memcached 11211). | `detectors/udp_flood_detector.py` |
| **Data Exfiltration** | `DATA_EXFILTRATION` | Evaluates asymmetric outbound byte ratios ($\ge 5.0\times$ sent vs received) combined with high sustained transfer volumes ($\ge 500\text{ KB}$) over a 10-second rolling window. | `detectors/exfiltration_detector.py` |
| **Botnet C2 Beaconing** | `C2_BEACONING` | Measures the **Coefficient of Variation ($CV \le 0.25$)** of inter-arrival connection times over a 300-second window to detect robotic, periodic command-and-control check-ins. | `detectors/beacon_detector.py` |
| **DGA & DNS Tunnelling** | `DGA_DNS_TUNNELLING` | Analyzes DNS query strings for **Shannon entropy ($H \ge 3.5$)**, oversized domain lengths, and query velocity to uncover algorithmically generated domains and data smuggling. | `detectors/dga_detector.py` |
| **TLS Metadata Anomaly** | `TLS_METADATA_ANOMALY` | Dissects unencrypted TLS `ClientHello` messages without decryption, calculating JA3 fingerprints and flagging structural anomalies (missing SNI, few cipher suites, repeated fingerprints). | `detectors/tls_detector.py` |
| **Unsupervised Anomaly Layer** | `ML_ANOMALY` | An `IsolationForest` model trained on 16 streaming network features that flags subtle, multi-dimensional behavioral outliers with explainable z-score evidence. | `inference/ml_detector.py` |

### Key System Features
- **Streaming 1-Second Sliding Windows:** Packets are processed in real time and aggregated into 1.0-second fixed analysis windows, preventing memory leaks during indefinite runs.
- **Bidirectional Flow Engine:** Automatically normalizes packet streams into bidirectional 5-tuple conversations and infers connection initiator vs. responder roles from TCP handshake flags.
- **Cross-Detector Incident Correlator:** Suppresses alert fatigue by collapsing related attack symptoms (e.g. folding SYN flood signals into active multi-port scans) and reassigning victim-side ML anomalies to the offending initiator as impact evidence.
- **Dual-Engine Persistence:** Fully functional out-of-the-box using embedded SQLite (`ctd_alerts.db` and `ctd_metrics.db`), with seamless, zero-reconfiguration promotion to PostgreSQL if configured.
- **PCAP Generation & Benchmarking Console:** Integrated tooling to generate multi-host synthetic traffic captures, replay them at custom speed multipliers or maximum speed, and score detection precision, recall, and F1 against ground-truth manifests.
- **Reactive SOC Web Interface:** Modern React 19 + Vite dashboard featuring live telemetry gauges, incident evidence drawers, interactive 3D attack timelines, and an interactive simulation laboratory.

---

## 4. Complete Technology Stack & Technical Rationale

```
┌────────────────────────────────────────────────────────────────┐
│                     FRONTEND DASHBOARD                         │
│   React 19 • Vite 8 • Three.js • React Three Fiber • Recharts  │
└───────────────────────────────┬────────────────────────────────┘
                                │ HTTP REST (JSON)
┌───────────────────────────────▼────────────────────────────────┐
│                      BACKEND REST API                          │
│          FastAPI • Uvicorn • Pydantic • Python 3.9+            │
└───────────────────────────────┬────────────────────────────────┘
                                │ SQL (psycopg 3 / sqlite3)
        ┌───────────────────────┴───────────────────────┐
        ▼                                               ▼
┌──────────────────────────────┐        ┌──────────────────────────────┐
│   DATABASE / STORAGE LAYER   │        │     INGESTION & ML ENGINE    │
│  PostgreSQL (Primary JSONB)  │◄───────┤  Scapy 2.7.0 (PcapReader)    │
│              OR              │        │  Scikit-Learn 1.9.0 (iForest)│
│  SQLite 3 (Cross-Process)    │        │  NumPy 2.5 • Pandas 3.0      │
└──────────────────────────────┘        └──────────────────────────────┘
```

| Technology | Selected Version | Role in Architecture | Technical Rationale |
| :--- | :--- | :--- | :--- |
| **Python** | `3.9+` | Core programming language | Rapid prototyping, extensive networking library ecosystem, and native data science support. |
| **FastAPI** | Latest | Asynchronous REST backend API | High-performance ASGI framework with automatic OpenAPI documentation and Pydantic validation. |
| **Uvicorn** | Latest | ASGI web server | Lightweight, lightning-fast async HTTP server hosting the FastAPI backend. |
| **Scapy** | `2.7.0` | Packet dissection & PCAP replay | Deep packet decoding across Ethernet, IP, TCP, UDP, ICMP, and DNS layers without requiring compiled C wrappers. |
| **Scikit-Learn** | `1.9.0` | Machine Learning anomaly engine | Provides the `IsolationForest` implementation used for unsupervised multi-feature outlier detection. |
| **Joblib** | `1.5.3` | Model persistence | High-performance serialization and loading of trained scikit-learn model weights. |
| **NumPy & Pandas** | `2.5.2`, `3.0.5` | Numerical processing & matrices | Efficient feature vector conversions, z-score calculations, and statistical rollups. |
| **PostgreSQL (`psycopg`)** | `3.3.4` | Relational database (Primary) | High concurrency, binary wire protocol, and native `JSONB` support for complex alert evidence. |
| **SQLite 3** | Standard Lib | Relational database (Fallback) | Zero-configuration file-based database allowing the engine to run without installing or starting a database server. |
| **React** | `19.2.8` | Frontend user interface | Declarative, component-based UI framework supporting concurrent rendering and real-time state updates. |
| **Vite** | `8.2.2` | Frontend build tool & bundler | Extremely fast development server with instant Hot Module Replacement (HMR). |
| **Three.js & R3F** | `0.186.0`, `9.7.0` | 3D visual canvas | Renders the interactive 3D incident timeline component on the Incidents page. |
| **Recharts & Chart.js** | `3.10.1`, `4.5.1` | Telemetry & threat charts | Smooth SVG/Canvas rendering of real-time bandwidth metrics, packet rates, and threat distributions. |
| **Lucide React** | `1.34.0` | Iconography | Comprehensive modern cybersecurity icon set for SOC alert cards and navigation. |

---

## 5. Project Objectives & Non-Functional Goals

1. **Deterministic Explainability:** In security operations, an alert without clear reasoning is ignored. Every alert generated by SentinelFlow-CTD includes an explicit `reasons` list detailing the exact threshold breaches (e.g., `high SYN ratio (0.95)`, `unusually few cipher suites offered (avg 2)`).
2. **Pipeline Feature Parity:** The features used to train the machine learning model (`inference/train_model_from_pcap.py`) are extracted through the **exact same code modules** (`FlowEngine`, `WindowManager`, `DNSTracker`, `TLSTracker`) that compute features during live inference. This guarantees zero training-serving skew.
3. **Resilience to Network Idle States:** A dedicated background thread (`background_flusher`) ensures that even if incoming network traffic drops to zero, pending observation windows are flushed and stale alerts are transitioned to `RESOLVED` after their 300-second inactivity period.
4. **Completely Self-Contained & Air-Gapped:** The engine has zero dependencies on external cloud APIs, threat intelligence lookups, or remote SaaS platforms. It operates entirely within isolated defense networks.
