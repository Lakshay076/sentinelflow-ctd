# SentinelFlow-CTD: Implementation Deep Dive

## 1. Introduction

This guide provides a comprehensive, module-by-module implementation walkthrough of the **SentinelFlow-CTD (MONI)** codebase. It examines the internal data structures, algorithms, mathematical thresholds, and control flows across every core component.

---

## 2. Bidirectional Flow Engine (`flow/flow_engine.py`)

### Purpose
Normalizes asymmetric, directional IP packets into bidirectional 5-tuple conversations and establishes connection roles (`initiator` vs. `responder`) by inspecting TCP handshake flags.

### Key Classes & Methods
- **`Flow` (Dataclass):**
  - Fields: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `start_time`, `last_seen`, `packets`, `bytes`, `forward_packets`, `backward_packets`, `forward_bytes`, `backward_bytes`, `initiator_ip`, `responder_ip`.
- **`FlowEngine._get_key(src_ip, dst_ip, src_port, dst_port, protocol)`:**
  - Sorts endpoint tuples lexicographically:
    ```python
    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)
    if endpoint_a <= endpoint_b:
        return (endpoint_a, endpoint_b, protocol)
    return (endpoint_b, endpoint_a, protocol)
    ```
  - This ensures that traffic from `Client:Port -> Server:80` and `Server:80 -> Client:Port` maps to the exact same flow object.
- **`FlowEngine.process_packet(packet: PacketRecord) -> Flow`:**
  - Evaluates TCP flags on incoming packets:
    - If `S` (SYN) is present and `A` (ACK) is absent, sets `flow.initiator_ip = packet.src_ip` and `flow.responder_ip = packet.dst_ip`.
    - If `S` and `A` are both present (SYN+ACK), verifies reverse-direction attribution.
  - Updates forward vs. backward packet and byte counters based on whether the packet matches the flow's initial direction.
- **`FlowEngine.is_new_flow(...) -> bool`:**
  - Checks if a packet begins a brand-new flow *without* mutating flow state. Used by `BeaconTracker` to only record the initial timestamp of new connections.

---

## 3. Streaming Feature Engineering (`features/`)

```
Packet Arrival
      │
      ├─► WindowManager (1.0s clock) ──► Fixed 1s Network & Security Features
      ├─► SourceAggregator            ──► Per-Source IP Metrics (bytes, ports, flows)
      ├─► BehaviorWindow (10.0s)      ──► Rolling Volume & Outbound/Inbound Ratio
      ├─► BeaconTracker (300.0s)      ──► Connection Inter-Arrival Coefficient of Variation
      ├─► DNSTracker (30.0s)          ──► Shannon Entropy of Domain Queries
      └─► TLSTracker & Parser (300.0s)──► Unencrypted ClientHello Metadata & JA3
```

### 1. `features/window.py` (`WindowManager` & `ObservationWindow`)
- **`ObservationWindow`:**
  - Aggregates basic counters: `packets`, `bytes`, directional byte ratios, protocol counts (`tcp_packets`, `udp_packets`, `icmp_packets`), TCP flags (`tcp_syn`, `tcp_ack`, `tcp_rst`), and unique sets (`source_ips`, `destination_ips`, `destination_ports`, `flows`).
  - `to_features(duration)` computes derived rates: `packets_per_second`, `bytes_per_second`, `mean_packet_size`, `syn_rate`, and `rst_rate`.
- **`WindowManager.add_packet(timestamp, **packet_data)`:**
  - Checks whether `timestamp < current.window_start + window_seconds`.
  - If the timestamp crosses the 1.0-second boundary, calls `to_features()`, instantiates a new `ObservationWindow`, and returns the completed feature dictionary.
- **`WindowManager.flush_if_ready(current_timestamp)`:**
  - Invoked by `background_flusher` during idle traffic periods to ensure windows close even when no new packets are arriving.

### 2. `features/source_aggregation.py` (`SourceAggregator`)
- Groups metrics per source IP within the current 1-second window.
- Critically, connection-attempt features (`destination_ips`, `destination_ports`, `tcp_syn`) are credited to the **`initiator_ip`**, while byte and packet counters track actual physical transmission direction.
- `get_features(duration)` computes per-source metrics: `outbound_inbound_ratio`, `flows_per_second`, `syn_packet_ratio`, and `ports_per_destination`.

### 3. `features/behavior_window.py` (`BehaviorWindow`)
- Implements a rolling 10.0-second sliding window using a `collections.deque` of packet events.
- On every packet, calls `_expire(current_timestamp)` to discard events older than `current_timestamp - 10.0`.
- Used by `exfiltration_detector.py` to identify sustained, asymmetric outbound transfers that span longer than 1 second.

### 4. `features/beacon_tracker.py` (`BeaconTracker`)
- Detects periodic C2 check-ins by analyzing connection start intervals over a 300.0-second (5-minute) rolling window.
- **Key Algorithm:**
  1. Filters out DNS traffic (port 53) to avoid flagging routine recursive DNS resolvers.
  2. For every `(src_ip, dst_ip)` pair with $\ge 2$ connections, computes intervals:
     $$\Delta t_i = t_{i+1} - t_i$$
  3. Calculates the mean ($\mu = \text{mean}(\Delta t)$) and standard deviation ($\sigma = \text{stdev}(\Delta t)$).
  4. Computes the **Coefficient of Variation ($CV$)**:
     $$CV = \frac{\sigma}{\mu}$$
  5. A low $CV$ ($CV \le 0.25$) indicates highly regular, robotic check-in timing.

### 5. `features/dns_tracker.py` (`DNSTracker`)
- Tracks DNS queries and response metadata over a 30.0-second rolling window using a bounded deque (`maxlen=500` per source IP).
- **Shannon Entropy Calculation:**
  ```python
  def calculate_entropy(text: str) -> float:
      length = len(text)
      counts = Counter(text)
      entropy = 0.0
      for count in counts.values():
          p = count / length
          entropy -= p * math.log2(p)
      return entropy
  ```
- **Character N-Gram Transition Anomaly Scoring (`calculate_ngram_anomaly`):**
  - Evaluates the proportion of character bigrams in queried domain labels that violate natural linguistic distributions or legitimate web domain naming patterns (e.g. consonant-digit alternations, rare consonant pairs like `qk`, `zq`, `xj`, `zf`).
  - Legitimate domains score $\le 0.20$; pseudo-random DGAs and base32/hex tunnels score $\ge 0.45$.
- **Domain Lexical Anomaly Scoring (`calculate_lexical_anomaly`):**
  - Detects longest consecutive consonant runs ($\ge 5$ is heavily penalized), elevated numeric digit ratios ($\ge 0.25$), and vowel-consonant imbalances.
- **Query-Type Distribution & Tunnelling Metadata:**
  - Tracks distribution across standard query types: `A`, `AAAA`, `TXT`, `CNAME`, `MX`, `PTR`, `NULL`, `ANY`.
  - Computes `dns_txt_query_count` and `dns_txt_query_ratio` to spot TXT-based tunnelling.
  - Measures `dns_mean_label_length`, `dns_max_label_length`, and `dns_long_label_ratio` ($\ge 30$ chars) to identify data encapsulation inside subdomain labels.
  - Captures `dns_mean_response_bytes` when downstream DNS responses are observed.
- Strictly bounded memory: Purges queries older than 30s with `_expire()` and evicts idle sources completely. Zero decryption of DoH/DoT; passive metadata analysis only.

### 6. `features/tls_parser.py` & `features/tls_tracker.py`
- Implements passive zero-decryption parsing of encrypted traffic setup metadata:
  - **TLS ClientHello (JA3 & JA4):**
    - Verifies TLS Record Type `0x16` (Handshake) and Handshake Type `0x01` (ClientHello).
    - Filters out GREASE values (`0x0a0a`, etc., RFC 8701).
    - Computes **JA3**: `SSLVersion,Ciphers,Extensions,Curves,PointFormats` and its MD5 hash.
    - Computes standards-compliant **FoxIO JA4**:
      - `JA4_a`: 10 characters (`protocol` `t`/`q` + `version` + `sni` `d`/`i` + `cipher_count` + `extension_count` + `alpn`).
      - `JA4_b`: 12 hex characters (SHA-256 hash of sorted 4-character hex cipher suites).
      - `JA4_c`: 12 hex characters (SHA-256 hash of sorted extensions excluding GREASE/SNI/ALPN + wire-order signature algorithms).
  - **TLS ServerHello (JA3S):**
    - Verifies Handshake Type `0x02` (ServerHello).
    - Extracts negotiated server version (supporting TLS 1.3 `supported_versions` extension), single selected cipher suite, and negotiated extensions.
    - Computes **JA3S**: `TLSVersion,SelectedCipher,Extensions` and its MD5 hash.
  - **QUIC / HTTP3 Passive Metadata (RFC 9000 / RFC 9369):**
    - Inspects UDP packets on ports 443/8443 for Long Header (`INITIAL`, `0-RTT`, `HANDSHAKE`, `RETRY`) and Short Header (`1-RTT`).
    - Extracts QUIC Version, Destination Connection ID (`DCID`), and Source Connection ID (`SCID`).
    - Extracts unencrypted ClientHello from Initial CRYPTO frames to generate QUIC JA4 (`q13...`). Does not claim visibility into encrypted frames.
  - **SPLT (Sequence of Packet Length and Time):**
    - Tracks bounded sequences ($N \le 20$) of packet sizes and inter-packet arrival times (IPT).
    - Computes `splt_mean_length`, `splt_length_stdev`, `splt_mean_ipt`, and `splt_ipt_cv` ($\sigma / \mu$) to identify robotic C2 beacons and fixed-size encrypted tunnelling.
- **`TLSTracker` (300.0s window):**
  - Manages bounded deques per source IP (`maxlen=300`), tracking ClientHello, ServerHello, QUIC, and SPLT features with sliding window expiration.

---

## 4. Threat Detection Engines (`detectors/`)

All heuristic detectors take a combined feature dictionary for a single source IP and return a `DetectionResult(detected, attack_type, severity, score, confidence, reasons)`.

```
Combined Source Features
           │
           ├─► detect_port_scan()        ──► PORT_SCAN
           ├─► detect_syn_flood()        ──► SYN_FLOOD
           ├─► detect_udp_flood()        ──► UDP_FLOOD
           ├─► detect_exfiltration()     ──► DATA_EXFILTRATION
           ├─► detect_c2_beaconing()     ──► C2_BEACONING
           ├─► detect_dga_dns()          ──► DGA_DNS_TUNNELLING
           ├─► detect_tls_anomaly()      ──► TLS_METADATA_ANOMALY
           └─► detect_ml_anomaly()       ──► ML_ANOMALY
```

### 1. `detectors/scan_detector.py` (`detect_port_scan`)
- Detects reconnaissance activity across three complementary scanning patterns:
  1. **Vertical Port Scan:** Probing multiple destination ports on single/few targets (service discovery).
  2. **Fast Horizontal Sweep:** High-rate probing of single/few destination ports across multiple targets within an instantaneous 1.0s window.
  3. **Slow-and-Low Horizontal Sweep:** Low-rate, stealthy host sweeps evaluated over the 10.0s rolling `BehaviorWindow` that bypass 1.0s rate thresholds.
- **Configurable Thresholds:**
  - `MIN_DESTINATION_PORTS = 5` (vertical scan)
  - `MIN_FLOWS = 5`
  - `MIN_SYN_RATIO = 0.60` (vertical scan)
  - `MIN_FLOWS_PER_SECOND = 5.0`
  - `MIN_DESTINATION_HOSTS = 8` (fast horizontal host sweep)
  - `MAX_HORIZONTAL_PORTS = 3` (concentrated port footprint across hosts)
  - `MIN_HORIZONTAL_FLOWS = 8`
  - `MIN_HORIZONTAL_SYN_RATIO = 0.50` (connection attempt dominance)
  - `MIN_HORIZONTAL_FLOW_RATE = 5.0`
  - `MIN_SLOW_SCAN_HOSTS = 8` (slow-and-low host sweep across rolling 10s window)
  - `MAX_SLOW_SCAN_PORTS = 3` (concentrated port profile)
  - `MIN_SLOW_SCAN_FLOWS = 8` (minimum connection attempts over 10s)
  - `MIN_SLOW_SCAN_SYN_RATIO = 0.50` (distinguishes reconnaissance from established browsing sessions)
  - `MIN_SLOW_SCAN_SYN_PACKETS = 6` (minimum SYN count to prevent false positives on sparse traffic)
- **Decision Rules:**
  - **Vertical Scan:** Probing multiple ports on a host with high SYN ratio:
    $$\text{is\_vertical} = (\text{unique\_ports} \ge 5) \land (\text{syn\_ratio} \ge 0.60) \land (\text{score} \ge 2)$$
  - **Fast Horizontal Sweep:** Probing a single or few ports across multiple hosts at high rate:
    $$\text{is\_fast\_horizontal} = (\text{unique\_destinations} \ge 8) \land (\text{unique\_ports} \le 3 \lor \text{ports/host} \le 1.0) \land (\text{syn\_ratio} \ge 0.50) \land (\text{active\_flows} \ge 8) \land (\text{score} \ge 3)$$
  - **Slow-and-Low Horizontal Sweep:** Stealthy sweep across destination hosts over the rolling 10-second `BehaviorWindow`:
    $$\text{is\_slow\_horizontal} = (\text{slow\_destinations} \ge 8) \land (\text{slow\_ports} \le 3 \lor \text{slow\_ppd} \le 1.0) \land (\text{slow\_syn\_ratio} \ge 0.50) \land (\text{slow\_flows} \ge 8) \land (\text{slow\_syn\_packets} \ge 6)$$
  - Final decision: $\text{detected} = \text{is\_vertical} \lor \text{is\_fast\_horizontal} \lor \text{is\_slow\_horizontal}$.
- **Distinguishing Slow Scans from Normal Browsing:**
  - Legitimate web browsing contacting multiple CDN/cloud endpoints exchanges substantial application payload and ACK packets, yielding $\text{syn\_ratio} \le 0.15$.
  - Stealthy port scans send probe packets without payload transfer, yielding $\text{syn\_ratio} \ge 0.50$.
  - Enforcing $\text{slow\_syn\_ratio} \ge 0.50$ and $\text{slow\_syn\_packets} \ge 6$ eliminates false positives while detecting stealthy reconnaissance.
- Confidence: $\min(\text{score} / 4.0, 1.0)$. Severity: $\ge 4$ points = `HIGH`, 3 points = `MEDIUM`, 2 points = `LOW`.
- Memory bounding: `BehaviorWindow._expire(timestamp)` purges events older than 10.0s using a sliding deque, keeping memory strictly $O(N_{\text{events in 10s}})$.

### 2. `detectors/syn_flood_detector.py` (`detect_syn_flood`)
- **Thresholds:**
  - `MIN_SYN_RATIO = 0.80`
  - `MIN_SYN_RATE = 50.0` SYN/s
  - `MIN_FLOWS_PER_SECOND = 50.0` flows/s
- **Decision Rule:**
  $$\text{detected} = (\text{score} \ge 2)$$
- Confidence: $\text{score} / 3.0$. Severity: 3 points = `HIGH`, 2 points = `MEDIUM`.

### 3. `detectors/udp_flood_detector.py` (`detect_udp_flood`)
- Detects high-rate UDP volumetric floods and reflection/amplification patterns.
- **Configurable Thresholds:**
  - `MIN_UDP_RATE = 50.0` UDP packets/sec
  - `MIN_UDP_RATIO = 0.80` (80% UDP dominance)
  - `MIN_UDP_BYTES_PER_SECOND = 50_000.0` (50 KB/s bandwidth footprint)
  - `MIN_UDP_PACKETS = 20` (minimum sample count to eliminate false positives)
  - `MIN_FLOWS_PER_SECOND = 20.0` (rapid creation of ephemeral UDP flows)
  - `WELL_KNOWN_REFLECTION_PORTS = {17, 19, 53, 123, 161, 389, 1900, 3702, 5353, 11211}`
- **Passive Monitoring Constraint:**
  - Operates completely passively: zero live socket transmissions, zero firewall rule changes, zero packet drops.
  - When unidirectional traffic is observed, does not claim a verified amplification ratio; reports suspicious volumetric UDP activity.
  - When bidirectional traffic is captured with high byte asymmetry ($\ge 5.0$), reports inferred amplification pattern.
- **Decision Rule:**
  $$\text{detected} = (\text{score} \ge 2)$$
- Confidence: $\min(0.60 + (\text{score} - 2) \times 0.15, 1.0)$. Severity: `HIGH` ($\text{score} \ge 4$ or $\ge 3$ with bandwidth $\ge 100\text{KB/s}$ or rate $\ge 100\text{pkts/s}$), `MEDIUM` ($\text{score} \ge 2$), `NONE`.

### 4. `detectors/network_entropy_detector.py` (`detect_distributed_udp_flood`)
- Network-level detector evaluating aggregate volume and source IP Shannon entropy:
  $$H_{\text{src}} = -\sum_{i=1}^{K} p_i \log_2(p_i), \quad H_{\text{norm}} = \frac{H_{\text{src}}}{\log_2(K)}$$
- Identifies distributed spoofed-source UDP floods where individual spoofed IPs send only 1–few packets to evade per-source thresholds.
- **Configurable Thresholds:**
  - `MIN_AGGREGATE_UDP_PACKETS = 40`
  - `MIN_AGGREGATE_UDP_RATE = 40.0` pkts/s
  - `MIN_AGGREGATE_UDP_BYTES_PER_SECOND = 40_000.0` (40 KB/s)
  - `MIN_UNIQUE_SOURCES = 10`
  - `MIN_NORMALIZED_SOURCE_ENTROPY = 0.75`
  - `MIN_SOURCE_ENTROPY_BITS = 3.0`
  - `MAX_MEAN_PACKETS_PER_SOURCE = 15.0` (spoofed traffic disperses 1-few packets per IP)
  - `MIN_UDP_PACKET_RATIO = 0.70`
- **Decision Rule:**
  Requires sufficient samples ($\ge 40$ pkts, $\ge 10$ sources) AND high entropy ($H_{\text{norm}} \ge 0.75$ or $H \ge 3.0$) AND $\text{score} \ge 3$.
- Confidence: $\min(0.65 + (\text{score} - 3) \times 0.15, 1.0)$. Severity: `HIGH` ($\text{score} \ge 4$ and rate $\ge 100\text{pkts/s}$ or bandwidth $\ge 80\text{KB/s}$), `MEDIUM` ($\text{score} \ge 3$).

### 5. `detectors/exfiltration_detector.py` (`detect_exfiltration`)
- Evaluates features from `BehaviorWindow` (10s rolling duration).
- **Thresholds:**
  - `MIN_OUTBOUND_BYTES = 500_000` (500 KB)
  - `MIN_RATIO = 5.0` ($5\times$ more sent than received)
  - `MIN_PACKETS = 20`
- **Decision Rule:**
  $$\text{detected} = (\text{bytes\_sent} \ge 500\text{KB}) \land (\text{ratio} \ge 5.0) \land (\text{score} \ge 3)$$
- Requiring both large volume and high asymmetry prevents flagging legitimate two-way file transfers.

### 6. `detectors/beacon_detector.py` (`detect_c2_beaconing`)
- Evaluates features from `BeaconTracker`.
- **Thresholds:**
  - `MIN_CONNECTIONS = 4`
  - `MAX_INTERVAL_CV = 0.25`
  - `MIN_MEAN_INTERVAL = 1.0` second
  - `MAX_REPEATED_DESTINATIONS = 3`
- **Decision Rule:**
  $$\text{detected} = (CV \le 0.25) \land (\text{connections} \ge 4) \land (\mu_{\text{interval}} \ge 1.0\text{s}) \land (\text{score} \ge 3)$$

### 7. `detectors/dga_detector.py` (`detect_dga_dns`)
- Evaluates multi-layered lexical, linguistic, and protocol features from `DNSTracker`.
- **Configurable Thresholds:**
  - `MIN_QUERY_COUNT = 5`
  - `MIN_HIGH_ENTROPY_RATIO = 0.50` (at least 50% of domains have $H \ge 3.5$)
  - `MIN_UNIQUE_DOMAINS = 5`
  - `MIN_MEAN_LENGTH = 35` characters
  - `MIN_QUERIES_PER_SECOND = 2.0`
  - `MIN_NGRAM_ANOMALY_RATIO = 0.40`
  - `MIN_MEAN_NGRAM_ANOMALY = 0.45`
  - `MIN_LEXICAL_ANOMALY_RATIO = 0.40`
  - `MIN_MEAN_LEXICAL_SCORE = 0.45`
  - `MIN_LONG_LABEL_RATIO = 0.30`
  - `MIN_MAX_LABEL_LENGTH = 30`
  - `MIN_TXT_QUERY_RATIO = 0.40`
  - `MIN_TXT_QUERY_COUNT = 5`
  - `MIN_RESPONSE_BYTES_ANOMALY = 512`
- **Detection Rules:**
  1. Shannon entropy: High proportion of random-looking domains ($H \ge 3.5$).
  2. Domain diversity: Querying $\ge 5$ distinct domains in a short window.
  3. Query length: Unusually long average domain name length ($\ge 35$ characters).
  4. Query velocity: Rapid query velocity ($\ge 2.0$ queries/second).
  5. Character n-gram anomaly: Unnatural character transition patterns violating natural language distributions.
  6. Lexical structure: Long consonant clusters ($\ge 5$), high digit ratios ($\ge 0.30$), or vowel-less strings.
  7. Long subdomain labels: Labels $\ge 30$ characters indicative of data encapsulation / chunking.
  8. Unusual TXT query distribution: Heavy TXT concentration ($\ge 40\%$) combined with suspicious payload indicators (entropy, long labels, or high domain diversity). TXT queries alone are NOT flagged to protect SPF/DKIM workloads.
  9. Oversized response payloads: Response sizes $\ge 512$ bytes when downstream responses are captured.
- **Decision Rule:**
  $$\text{detected} = (\text{query\_count} \ge 5) \land (\text{score} \ge 2)$$
- Confidence: $\min(\text{score} / 4.0, 1.0)$. Severity: $\ge 4$ = `HIGH`, 3 = `MEDIUM`, 2 = `LOW`.

### 8. `detectors/tls_detector.py` (`detect_tls_anomaly`)
- Evaluates structural ClientHello, JA3, JA4, and SPLT features from `TLSTracker`.
- **Configurable Thresholds:**
  - `MIN_CIPHER_COUNT_SUSPICIOUS = 5` (real browsers offer 15+)
  - `MIN_EXTENSION_COUNT_SUSPICIOUS = 4`
  - `MIN_MISSING_SNI_RATIO = 0.50`
  - `MIN_REPEATED_IDENTICAL_HELLOS = 5` (JA3 repetition)
  - `MIN_REPEATED_JA4 = 5` (JA4 repetition)
  - `MIN_SPLT_TIMING_CV_SUSPICIOUS = 0.15` (robotic inter-packet arrival jitter)
  - `MIN_SPLT_LENGTH_STDEV_SUSPICIOUS = 10.0` (fixed-size encrypted tunnelling)
- **Detection Rules:**
  1. Cipher suites: Unusually few ciphers offered ($\le 5$).
  2. Extensions: Unusually few extensions offered ($\le 4$).
  3. Missing SNI: Server Name Indication missing in $\ge 50\%$ of handshakes.
  4. Fingerprint repetition: Identical JA3 or JA4 fingerprint repeated to the same destination $\ge 5$ times.
  5. SPLT timing sequence: Extremely low timing jitter ($CV \le 0.15$ with $\ge 5$ packets) indicative of automated C2 beaconing.
  6. SPLT packet length sequence: Uniform packet sizes (stdev $\le 10$ bytes with $\ge 8$ packets and mean size $\ge 300$ bytes) indicative of fixed-block encrypted tunnelling.
- **Decision Rule:**
  $$\text{detected} = (\text{score} \ge 2)$$
- Confidence: $\min(\text{score} / 4.0, 1.0)$. Severity: $\ge 4$ = `HIGH`, 3 = `MEDIUM`, 2 = `LOW`.

---

## 5. Machine Learning Anomaly Detection (`inference/`)

### 1. Feature Schema (`inference/feature_schema.py`)
Defines the 16-dimensional feature vector:
```python
FEATURE_NAMES = [
    "packets_per_second", "bytes_per_second", "syn_packet_ratio",
    "rst_packet_ratio", "unique_destinations", "unique_destination_ports",
    "active_flows", "flows_per_second", "ports_per_destination",
    "bytes_received", "outbound_inbound_ratio", "beacon_interval_cv",
    "dns_high_entropy_ratio", "dns_queries_per_second",
    "tls_avg_cipher_count", "tls_missing_sni_ratio"
]
```
`features_to_vector()` imputes missing features using `DEFAULT_VALUES`, ensuring absent signals (e.g. no DNS traffic) reflect benign defaults rather than zeros.

### 2. Model Inference & Explainability (`inference/ml_detector.py`)
- Lazy-loads `model.joblib` and `feature_stats.json`.
- Evaluates active traffic gate: sources with $< 5$ packets, $< 500$ bytes, and $< 3$ flows are treated as idle background and skipped.
- **Prediction:**
  $$\text{prediction} = \text{model.predict}([v]), \quad \text{raw\_score} = \text{model.decision\_function}([v])$$
  $$\text{is\_anomaly} = (\text{prediction} == -1) \land (\text{raw\_score} < -0.04)$$
- **Explainable Evidence Generation (`_explain`):**
  - For each feature, calculates the z-score against benign baseline statistics:
    $$z = \frac{v_i - \mu_i}{\sigma_i}$$
  - If $\sigma_i < 10^{-4}$ (near-constant feature), reports absolute deviation.
  - Sorts features by $|z|$ and reports the top 3 deviating features in plain English (e.g., `syn_packet_ratio unusually higher than normal (value=0.95, z-score=4.2)`).

---

## 6. Incident Correlation & Attribution (`detectors/incident_correlator.py`)

The `IncidentCorrelator` acts as the bridge between raw detection results and operator-facing incidents:

1. **Reconnaissance & SYN Flood Collapsing:**
   - When a source triggers both `PORT_SCAN` and `SYN_FLOOD` with $\ge 10$ unique ports and $\ge 5.0$ ports per destination, the SYN flood is removed as a standalone incident and folded into the `PORT_SCAN` alert:
     ```python
     supporting_reasons = [
         "SYN activity correlated with multi-port reconnaissance",
         f"SYN flood detector signal observed across {unique_ports} destination ports"
     ]
     ```
2. **Victim Impact Attribution (`correlate_victim_impact`):**
   - If an external initiator launches a known attack (e.g., `SYN_FLOOD`), and the target responder host triggers an `ML_ANOMALY` due to resource exhaustion, the correlator:
     1. Extracts the victim's ML anomaly reasons and confidence.
     2. Appends them to the attacker's `SYN_FLOOD` alert under `reasons` as `Victim-side ML impact anomaly`.
     3. Removes the victim host from the active attacker alerts table.
3. **ML Corroboration:**
   - If a host triggers both a rule detector and `ML_ANOMALY`, the rule alert remains primary and the ML confidence is attached as corroborating evidence.

---

## 7. State & Persistence Engine (`alerts/` & `telemetry/`)

### `AlertManager` (`alerts/alert_manager.py`)
- **Deduplication:** When an alert is reported, `store.find_active(source_ip, attack_type)` checks if an open incident exists:
  - If `None`: calls `store.create()`.
  - If existing: calls `store.update()`, bumping `last_seen`, elevating `confidence = max(existing, new)`, and incrementing `event_count`.
- **Stale Resolution:** `resolve_stale(timestamp)` checks active alerts against `resolve_after = 300.0`. Inactive incidents are marked `RESOLVED`.

### `AlertStore` (`alerts/alert_store.py`)
- On instantiation, tests the connection string in `DATABASE_URL`:
  ```python
  if self.database_url and "YOUR_PASSWORD" not in self.database_url:
      try:
          import psycopg
          with psycopg.connect(self.database_url, connect_timeout=1) as conn:
              # Initialize PostgreSQL tables with JSONB columns
          self.use_postgres = True
      except Exception:
          self.use_postgres = False
  ```
- If PostgreSQL fails or is unconfigured, calls `_init_sqlite()` to initialize `ctd_alerts.db`.
- Both database engines share identical CRUD signatures (`create`, `get`, `all`, `active`, `update`, `resolve`, `clear_history`, `clear_all`).
