# SentinelFlow-CTD (MONI) — Performance Benchmark & Resource Profiling Report
**Target Challenge:** NTRO Smart India Hackathon Problem Statement ID 26145  
**Challenge Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Auditor:** Senior Cybersecurity Architect & AI/ML Systems Engineer  
**Audit Date:** November 2026 (Final Evidence Reconciliation)  
**Repository Working Directory:** `d:\Projects\sentinelflow-ctd`  

---

## 1. Executive Summary & Measurement Environment

This benchmark report provides reconciled empirical measurements of system throughput, phase-by-phase latency distributions, CPU utilization, peak memory footprint, and packet drop statistics for **SentinelFlow-CTD**.

### 1.1 Strict Ingestion Mode Differentiation
To prevent misrepresenting prototype measurements, three distinct operational modes are explicitly distinguished throughout this report:
1. **Offline PCAP Replay Mode:** Packets are read sequentially from disk using Scapy's `PcapReader`. No network interface is bound; packet delivery is limited by disk read and single-threaded Python CPU processing.
2. **Synthetic In-Memory Stream Mode:** Pre-allocated Scapy packet objects are fed from RAM directly into `process_packet()`. Eliminates disk I/O and Scapy packet generation overhead, measuring pure pipeline throughput.
3. **Live Interface Capture Mode:** Packets are captured from a physical/virtual NIC using Scapy's `sniff(store=False)`. Limited by OS socket buffer depth (Npcap on Windows) and kernel-to-userspace context switches.

> [!WARNING]
> Benchmarks measured via offline PCAP replay or in-memory synthetic streams **must not be characterized as live network wire throughput**. In live capture, Windows Npcap socket buffers drop packets when the single-threaded pipeline is blocked during synchronous window evaluation.

### 1.2 System & Benchmark Environment Metadata
- **Operating System:** Windows 11 Enterprise/Pro (Build 10.0.26200), AMD64
- **Processor:** Intel64 Family 6 Model 154 Stepping 3, GenuineIntel (12 logical cores, base clock 2.3 GHz)
- **Memory:** 16 GB Physical RAM
- **Python Version:** 3.14.2 64-bit (CPython)
- **Scapy Version:** 2.7.0
- **Storage Subsystem:** Local SSD (NTFS)
- **Measurement Methodology:** Python `time.perf_counter` (nanosecond precision wall clock), `time.process_time` (user+system CPU clock), and `tracemalloc` (byte-level heap allocator tracking). Benchmark runs preceded by a 1.0s warm-up iteration.

---

## 2. Reconciled Latency Phase Breakdown

Using instrumented micro-benchmarking on `demo.pcap` (54 windows, 917 packets), execution latency was decoupled across all five pipeline phases:

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

*\*Note on Ingestion Mean Latency:* Between window boundaries, per-packet ingestion takes only **$46.3\,\mu\text{s}$**. However, because window evaluation executes synchronously on the ingestion thread, the single packet that crosses a 1.0s boundary absorbs the entire $\sim 230\,\text{ms}$ window evaluation pause before returning, causing mean packet latency to register at $10.67\,\text{ms}$.

\*\*Note on Packet-to-Alert Latency:* The elapsed time from an attacker's *first* flow packet to alert generation depends on the attack signature type:
- **Volumetric Attacks (`SYN_FLOOD`, `UDP_FLOOD`, `PORT_SCAN`):** Alert emitted at the very first window boundary after the threshold is met ($0.2 - 1.2\text{ seconds}$).
- **Behavioral Attacks (`C2_BEACONING`, `DATA_EXFILTRATION`):** Requires observing $\ge 4$ check-in intervals (e.g. $4 \times 5\text{s} = 20\text{s}$) or accumulating 500 KB over a 10s behavior window.

---

## 3. Synthetic Load Tier Benchmarks & Drop Statistics

To determine the pipeline throughput ceiling and evaluate drop rates, synthetic traffic streams were ingested at four fixed arrival tiers (100, 500, 1000, 2500 pps) with pre-allocated memory packets:

| Ingestion Tier | Offered Packets | Processed Packets | Application Drops | Capture-Layer Drops (PCAP/Mem) | Achieved Throughput (pps) | Achieved Throughput (Mbps) | CPU % | Packet Latency P50 ($\mu\text{s}$) | Packet Latency P95 ($\mu\text{s}$) | Window Eval P95 (ms) | Peak Heap RAM (MB) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **100 pps** | 200 | 200 | **0 (0.00%)** | 0 | **129.3 pps** | **0.17 Mbps** | 98.0% | 1,235.5 | 1,775.2 | 635.37 | 5.86 MB |
| **500 pps** | 1,000 | 1,000 | **0 (0.00%)** | 0 | **308.7 pps** | **0.41 Mbps** | 92.1% | 1,298.2 | 1,871.2 | 881.66 | 13.21 MB |
| **1,000 pps** | 2,000 | 2,000 | **0 (0.00%)** | 0 | **396.5 pps** | **0.53 Mbps** | 95.7% | 1,349.5 | 1,936.5 | 972.72 | 23.31 MB |
| **2,500 pps** | 5,000 | 5,000 | **0 (0.00%)** | 0 | **496.7 pps** | **0.67 Mbps** | 97.3% | 1,384.7 | 1,997.1 | 1,076.71 | 52.54 MB |

### Drop Statistics & Bottleneck Analysis:
1. **Application-Level Dropped Packets: 0 (0.00% drop rate)**  
   The application pipeline processes every packet delivered to it without internal queue drops.
2. **Throughput Ceiling ($496.7\text{ pps}$ / $0.67\text{ Mbps}$):**  
   As offered packet rate increases from 100 to 2,500 pps, achieved throughput saturates at $\sim 500\text{ pps}$. This ceiling is imposed by:
   - Synchronous window evaluations taking $\sim 630 - 1,070\text{ ms}$ per second of packet time.
   - Single-threaded CPython GIL constraints.
3. **Capture-Layer Implications for Live Ingestion:**  
   In live network capture on a Gigabit interface, incoming traffic at line rate ($> 10,000\text{ pps}$) will overrun OS socket buffers (Npcap) during the 1-second window evaluation pause, causing significant capture-layer packet loss unless a decoupled ring buffer is introduced.

---

## 4. Real PCAP Replay Benchmarks

| Benchmark Dataset | Total Packets | Total Bytes | Duration | Sustained pps | Sustained Mbps | Flow Rate | CPU % | Window Count | Peak Heap Memory |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`demo.pcap`** | 917 | 712,232 | 34.09 s | **26.9 pps** | **0.17 Mbps** | 10.2 flows/s | 96.2% | 54 | 100.69 MB |
| **`benign.pcap`** | 300 | 63,217 | 17.05 s | **17.6 pps** | **0.03 Mbps** | 17.6 flows/s | 97.3% | 32 | 7.70 MB |

---

## 5. Production Scaling Comparison: Prototype vs C/eBPF/DPDK

| Dimension | SentinelFlow-CTD Prototype | Production Target (C / eBPF / DPDK) | Technical Justification |
| :--- | :--- | :--- | :--- |
| **Ingestion Engine** | Scapy `PcapReader` / `sniff(store=False)` | DPDK Poll Mode Driver / AF_XDP zero-copy | Kernel bypass eliminates socket buffer drops. |
| **Sustained Packet Rate** | $27 - 497\text{ packets/sec}$ | $1,000,000 - 10,000,000\text{ pps}$ | Multi-core lockless ring buffer scaling. |
| **Sustained Throughput** | $0.17 - 0.67\text{ Mbps}$ | $10\text{ Gbps} - 40\text{ Gbps}$ wire speed | $O(1)$ C header parsing vs Scapy object trees. |
| **Per-Packet Latency (P50)**| $46.3\,\mu\text{s}$ | $\le 1.5\,\mu\text{s}$ | Cache-aligned contiguous struct processing. |
| **Window Boundary Latency**| $229 - 1,076\,\text{ms}$ (synchronous) | $\le 5\,\text{ms}$ (asynchronous worker pool) | Decoupled ingest queue absorbs packet bursts. |
| **Memory Footprint** | Bounded in-memory deques ($7 - 100\text{ MB}$) | Fixed shared-memory pool ($512\text{ MB}$) | Zero dynamic runtime heap allocation. |
| **Alert Latency Definition**| Window closure + Eval ($0.2 - 1.2\text{s}$) | Micro-sliding window ($50 - 100\text{ms}$) | Sub-second real-time alert dispatch. |

---

## 6. Known Limitations and Unverified Claims

1. **Capture-Layer Live Packet Drops:** Sustained throughput in live NIC capture is bounded by single-core GIL processing. At line rates exceeding $\sim 500\text{ pps}$, Npcap socket buffer drops will occur.
2. **Synchronous Pipeline Blocking:** Window evaluation blocks packet ingestion on the main thread for $180 - 1,000\text{ ms}$, creating tail latency jitter.
3. **No Direct Hardware Acceleration:** Prototype relies on Python libraries; production 10 Gbps requires C/DPDK data plane implementation.
