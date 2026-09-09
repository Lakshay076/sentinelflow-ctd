# SentinelFlow-CTD (Cyber Threat Detection Engine)

A real-time, passive network cyber threat detection and monitoring system built for high-throughput gateway observation and SIH-aligned security challenges.

---

## Key Capabilities & Threat Coverage

1. **Reconnaissance / Port Scanning** (`PORT_SCAN`) — Destination port and host fanout analysis.
2. **Volumetric DDoS / SYN Flood** (`SYN_FLOOD`) — SYN surge rate and incomplete handshake tracking.
3. **Data Exfiltration** (`DATA_EXFILTRATION`) — Asymmetric egress flow byte ratio anomalies.
4. **Botnet C2 Beaconing** (`C2_BEACONING`) — Low coefficient of variation in periodic check-in timing.
5. **DGA & DNS Tunnelling** (`DGA_DNS_TUNNELLING`) — High-entropy Shannon randomness & oversized domain queries.
6. **TLS Metadata Anomaly** (`TLS_METADATA_ANOMALY`) — Unencrypted ClientHello parsing, JA3 fingerprinting, and missing SNI.
7. **Unsupervised ML Outlier Layer** (`ML_ANOMALY`) — 16-feature Isolation Forest with explainable z-score evidence.

---

## Architecture & SIH Alignment

- **Read-Only Ingest:** Uses `collector.pcap_replay_collector` via `PcapReader` (physically unable to transmit or modify packets, mirroring a hardware data diode).
- **Multi-Host Gateway Ingest:** Ingests simulated multi-host gateway traffic generated via `scripts/generate_synthetic_traffic.py` or real captures.
- **ML Trained on Replayed Pipeline Features:** Trained on feature vectors extracted through the same 1-second streaming window pipeline via `inference/train_model_from_pcap.py`.
- **Demonstrated Throughput Target:** Tracks and outputs sustained pps, Mbps, and flows/sec benchmark metrics.

---

## Quickstart & Usage

### 1. Environment Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 2. Run API Backend
```bash
uvicorn api.main:app --reload --port 8000
```

### 3. Run Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```
Open **http://localhost:5173** to view the live threat matrix, PCAP replay console, and benchmark gauges.

---

## PCAP Ingestion & Benchmarking Workflow

```bash
# 1. Generate multi-host gateway traffic with embedded attack scenarios
python scripts/generate_synthetic_traffic.py --out demo.pcap

# 2. Replay PCAP through streaming pipeline (Benchmark Mode)
python -m collector.pcap_replay_collector demo.pcap --max-speed

# 3. Validate detection accuracy against ground truth manifest
python scripts/validate_detections.py demo.pcap.ground_truth.json

# 4. Train ML Isolation Forest model on benign PCAP capture
python scripts/generate_synthetic_traffic.py --out benign.pcap --attacks
python -m inference.train_model_from_pcap benign.pcap
```

---

## Running Test Suites

```bash
# Run detector verification tests across all threat vectors
python -m tests.test_all_attacks

# Run API and PCAP replay integration tests
python -m tests.test_api_endpoints
```

---

## Network Interface Notes (`en0` vs PCAP Replay)

- **For PCAP Replay (`pcap_replay_collector.py`):** No network interface is required. The collector reads directly from the PCAP file on disk.
- **For Live Sniffing (`packet_collector.py`):** The default interface is `en0` on macOS (Wi-Fi/Ethernet). You can specify any interface without editing code:
  ```bash
  python -m collector.packet_collector lo0
  # Or via environment variable:
  CTD_INTERFACE=eth0 python -m collector.packet_collector
  ```
