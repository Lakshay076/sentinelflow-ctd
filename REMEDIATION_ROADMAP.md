# SentinelFlow-CTD (MONI) — Known Limitations & Prioritized Remediation Roadmap
**Target Challenge:** NTRO Smart India Hackathon Problem Statement ID 26145  
**Challenge Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Auditor:** Senior Cybersecurity Architect & AI/ML Systems Engineer  
**Audit Date:** November 2026 (Final Evidence Reconciliation)  
**Repository Working Directory:** `d:\Projects\sentinelflow-ctd`  

---

## 1. Executive Summary

This document establishes the technical limitations identified during the comprehensive audit and validation of **SentinelFlow-CTD (MONI)**, accompanied by an actionable, prioritized engineering remediation roadmap.

All recommendations are backed by empirical profiling data, source code audits, and mathematical analysis of detector boundaries.

---

## 2. Concise List of Unresolved Issues & Recommended Fixes

| Issue ID | Module / Component | Severity | Unresolved Problem Description | Recommended Fix | Effort Estimate |
| :---: | :--- | :---: | :--- | :--- | :---: |
| **ISSUE-01** | `inference/ml_detector.py` | **HIGH** | Default `IsolationForest` model weights are trained on synthetic Gaussian data, producing a 10% false positive rate on benign web traffic. | Execute `inference/train_model_from_pcap.py` against a 1-hour capture of real benign browsing (e.g. CICIDS2017) to learn true multimodal traffic variances. | 4 hours |
| **ISSUE-02** | `detectors/scan_detector.py` | **MEDIUM** | Horizontal port scan heuristic flagged benign host `10.0.0.17` because it contacted 9 external CDNs on ports 80/443 within a few seconds. | Differentiate port sensitivity: require $\ge 15$ destination hosts for standard web ports (`80`, `443`), while maintaining the $\ge 8$ threshold for administrative ports (`22`, `445`, `3389`). | 2 hours |
| **ISSUE-03** | `collector/packet_collector.py` | **HIGH** | Ingestion thread synchronously executes window evaluation, blocking packet ingestion for $180 - 1,000\text{ ms}$ at every 1-second boundary. | Decouple ingestion from window evaluation using a lockless single-producer single-consumer (SPSC) ring buffer queue. | 3 days |
| **ISSUE-04** | `collector/packet_collector.py` | **HIGH** | Scapy pure-Python layer parsing allocates heavy heap object trees per packet, capping throughput to $\sim 500\text{ pps}$ ($0.67\text{ Mbps}$). | Replace Scapy with a C-accelerated packet parser (`pypcap`, `dpkt`, or AF_XDP/DPDK driver) operating directly on raw byte offsets. | 1 week |
| **ISSUE-05** | `features/tls_parser.py` | **MEDIUM** | QUIC Initial ClientHello extraction uses naive string searching (`\x16\x03`) and fails on real RFC 9000 encrypted Initial packets. | Implement HKDF-Extract / HKDF-Expand-Label using RFC 9000 Initial salt (`0x38762cf7...`) and AES-128-GCM to decrypt Initial CRYPTO frames before parsing. | 4 days |
| **ISSUE-06** | `collector/` (Ingest Adapters) | **MEDIUM** | Router flow telemetry (NetFlow v9 / IPFIX) is not supported; only raw PCAP and live interfaces are ingested. | Implement lightweight UDP collector on ports 2055/4739 to parse flow record templates directly into `PacketRecord` format. | 2 weeks |
| **ISSUE-07** | `features/beacon_tracker.py` | **LOW** | Botnet C2 tracking only monitors the single most-contacted destination IP per source, missing fast-flux or CDN-rotating botnets. | Cluster destination connections by autonomous system number (ASN) or second-level domain before computing timing coefficient of variation. | 1 week |

---

## 3. Prioritized Engineering Roadmap

```
[Phase P0: Immediate Calibration & Model Tuning] (1-2 Days)
  ├── P0.1: Retrain Isolation Forest on Real Benign PCAP (Eliminates 2 False Positives)
  └── P0.2: Calibrate Horizontal Port Scan Exclusions for Web Ports (Eliminates 1 False Positive)
         │
         ▼
[Phase P1: Ingestion & Pipeline Architecture] (1-2 Weeks)
  ├── P1.1: Decouple Ingestion from Window Evaluation via Ring Buffer (Sub-ms Latency)
  └── P1.2: Integrate C-Accelerated Packet Parser (DPDK / AF_XDP / PyShark)
         │
         ▼
[Phase P2: Protocol & Telemetry Expansion] (2 Weeks)
  ├── P2.1: Implement RFC 9000 QUIC Initial Packet HKDF Decryption
  └── P2.2: Implement NetFlow v9 & IPFIX Flow Record Ingest Adapter
         │
         ▼
[Phase P3: Advanced Threat Correlation & Streaming UI] (2-3 Weeks)
  ├── P3.1: Implement Multi-IP Distributed C2 Beacon Tracking (ASN Clustering)
  └── P3.2: Replace Dashboard Polling with WebSocket Streaming Telemetry
```

---

## 4. Known Limitations and Unverified Claims

1. **Not Production Ready for Gigabit Line Rates:** Passing all unit tests does not qualify the Python/Scapy prototype for multi-gigabit enterprise peering links. Without a C/DPDK decoupled ring buffer, live ingestion will experience capture-layer socket buffer drops under heavy traffic.
2. **QUIC Initial Payload Decryption Unimplemented:** Wire header metadata (Version, DCID, SCID, packet types) is implemented and verified. Initial CRYPTO frame decryption via RFC 9000 HKDF secrets is **not implemented**. ClientHello extraction does not function on real encrypted QUIC wire captures.
3. **Encrypted Client Hello (ECH):** In TLS 1.3 with ECH, the inner SNI is encrypted and unavailable to passive sensors. Outer SNI/grease values are parsed.
4. **ML Training Baseline:** Shipped Isolation Forest model is trained on synthetic data. Generates 2 false positives on benign browsing traffic.
5. **Router Telemetry Ingestion:** Direct NetFlow/IPFIX UDP collection is not implemented; PCAP replay and live interface capture are the supported ingestion paths.
