# SentinelFlow-CTD: Repository Structure & File Directory

## 1. Complete Directory Tree

Below is the verified file tree of the SentinelFlow-CTD repository:

```
D:/Projects/sentinelflow-ctd/
├── .env.example                                  # Sample environment variables template
├── .gitignore                                    # Git exclusion rules
├── benign.pcap                                   # Reference benign capture for ML model training
├── benign.pcap.ground_truth.json                 # Ground-truth labels for benign.pcap
├── demo.pcap                                     # Synthetic multi-host PCAP with embedded attacks
├── demo.pcap.ground_truth.json                   # Ground-truth labels for demo.pcap
├── notes.txt                                     # CLI quick-reference and attack simulation snippets
├── PROJECT_CONTEXT.md                            # High-level architecture and developer notes
├── README.md                                     # Project overview and quickstart guide
├── requirements.txt                              # Python backend dependency manifest
│
├── alerts/                                       # Alert management and persistence
│   ├── __init__.py
│   ├── alert_manager.py                          # Alert deduplication and lifecycle management
│   ├── alert_record.py                           # AlertRecord dataclass definition
│   └── alert_store.py                            # Dual PostgreSQL / SQLite persistence layer
│
├── api/                                          # FastAPI REST application
│   ├── __init__.py
│   ├── main.py                                   # FastAPI entry point, middleware, and root routes
│   └── routes/                                   # Route controllers
│       ├── __init__.py
│       ├── alerts.py                             # Alert retrieval, simulation, and resolution
│       ├── metrics.py                            # Live telemetry feeds
│       └── pcap.py                               # PCAP generation, replay, and validation
│
├── collector/                                    # Network packet ingestion engines
│   ├── __init__.py
│   ├── packet_collector.py                       # Live interface sniffer (`sniff()`) & window driver
│   ├── packet_record.py                          # PacketRecord dataclass (sanitized metadata)
│   └── pcap_replay_collector.py                  # Read-only PCAP replay engine (`PcapReader`)
│
├── demo/                                         # Controlled in-memory simulation engine
│   ├── __init__.py
│   └── simulator.py                              # Generates in-memory Scapy packets for UI triggers
│
├── detectors/                                    # Threat detection algorithms & correlation
│   ├── __init__.py
│   ├── beacon_detector.py                        # C2 beaconing timing regularity detector
│   ├── correlation.py                            # Communication relationship context builder
│   ├── detection_result.py                       # DetectionResult dataclass
│   ├── detector_engine.py                        # Central detection orchestrator
│   ├── dga_detector.py                           # DGA domain entropy & DNS tunneling detector
│   ├── exfiltration_detector.py                  # Asymmetric outbound byte volume detector
│   ├── incident_correlator.py                    # Multi-threat correlation & victim attribution
│   ├── scan_detector.py                          # Port scan & reconnaissance detector
│   ├── syn_flood_detector.py                     # Volumetric TCP SYN flood detector
│   └── tls_detector.py                           # TLS ClientHello metadata anomaly detector
│
├── docs/                                         # Technical documentation knowledge base
│   ├── ARCHITECTURE.md                           # System architecture & Mermaid sequence flows
│   ├── FOLDER_STRUCTURE.md                       # This document: codebase layout & entry points
│   ├── MODEL_AND_FEATURES.md                     # Detailed heuristic and ML feature definitions
│   ├── PROJECT_OVERVIEW.md                       # High-level project problem statement & goals
│   └── SIH_ALIGNMENT.md                          # Hackathon challenge alignment notes
│
├── features/                                     # Streaming feature extraction & temporal windows
│   ├── __init__.py
│   ├── beacon_tracker.py                         # 300s rolling window for C2 inter-arrival times
│   ├── behavior_window.py                        # 10s rolling window for sustained data exfiltration
│   ├── communication_context.py                  # Initiator vs responder relationship tracker
│   ├── dns_tracker.py                            # 30s rolling window for Shannon entropy
│   ├── feature_context.py                        # Central FeatureContext carrier object
│   ├── flow_features.py                          # Flow-level helper statistics
│   ├── security_features.py                      # Derived ratios (SYN/ACK ratio, flow density)
│   ├── source_aggregation.py                     # Per-source IP metric rollups for 1s window
│   ├── streaming_features.py                     # Streaming aggregate helpers
│   ├── tls_parser.py                             # Zero-decryption ClientHello & JA3 parser
│   ├── tls_tracker.py                            # 300s rolling window for TLS fingerprint counts
│   └── window.py                                 # WindowManager & ObservationWindow (1.0s clock)
│
├── flow/                                         # Connection tracking engine
│   ├── __init__.py
│   └── flow_engine.py                            # FlowEngine (bidirectional 5-tuple session tracker)
│
├── inference/                                    # Machine learning anomaly detection
│   ├── __init__.py
│   ├── feature_schema.py                         # 16-feature vector definition & default values
│   ├── feature_stats.json                        # Baseline mean and standard deviation stats
│   ├── ml_detector.py                            # Isolation Forest inference & z-score explainer
│   ├── model.joblib                              # Serialized trained IsolationForest model weights
│   └── train_model_from_pcap.py                  # Model trainer using the streaming pipeline
│
├── scripts/                                      # Standalone CLI tools
│   ├── generate_synthetic_traffic.py             # Generates gateway PCAP captures with attack labels
│   └── validate_detections.py                    # Computes precision, recall, and F1 against ground truth
│
├── telemetry/                                    # Real-time network throughput store
│   ├── __init__.py
│   └── live_metrics.py                           # Rolling 60-second telemetry persistence
│
├── tests/                                        # Comprehensive test suite (24 test files)
│   ├── __init__.py
│   ├── test_all_attacks.py                       # Verifies all 7 threat detectors against mock features
│   ├── test_api_endpoints.py                     # Tests FastAPI route responses and simulation hooks
│   └── ...                                       # Unit tests for flow, windows, and storage
│
└── frontend/                                     # React 19 + Vite dashboard application
    ├── index.html                                # HTML root template
    ├── package.json                              # Node dependencies & npm scripts
    ├── package-lock.json                         # Node dependency lockfile
    ├── vite.config.js                            # Vite bundler configuration
    ├── .oxlintrc.json                            # Oxlint linter configuration
    ├── public/                                   # Static icons (favicon.svg, icons.svg)
    └── src/
        ├── main.jsx                              # React application entry point
        ├── App.jsx                               # Root application component & polling controller
        ├── config.js                             # API endpoints and detector configurations
        ├── utils.js                              # Formatting helpers (attack names, timestamps)
        ├── index.css                             # Global CSS reset
        ├── App.css                               # Root layout and shell styling
        ├── components/                           # Reusable UI widgets
        │   ├── AboutArchitecture.jsx             # Visual pipeline diagram widget
        │   ├── AboutBackground.jsx               # Decorative animated background canvas
        │   ├── AlertCard.jsx                     # SOC alert card with severity badges
        │   ├── AnalyticsTrendChart.jsx           # Bandwidth and flow trend visualizer
        │   ├── AttackClassChart.jsx              # Threat distribution bar chart
        │   ├── Badges.jsx                        # Status and severity pill badges
        │   ├── DemoPipelineVisualization.jsx     # Interactive pipeline stage visualizer
        │   ├── IncidentDrawer.jsx                # Detailed incident evidence slide-out panel
        │   ├── IncidentTimeline3D.jsx            # Interactive 3D incident timeline (Three.js)
        │   ├── LiveTrafficChart.jsx              # Real-time packet-per-second line chart
        │   ├── Reveal.jsx                        # Scroll-reveal animation container
        │   ├── ScrollBackground.jsx              # Dynamic background particle grid
        │   ├── StatCard.jsx                      # KPI stat counter card
        │   └── ThreatConnectionGraph.jsx         # Host interaction link graph
        ├── pages/                                # Dashboard view pages
        │   ├── AboutMoniPage.jsx                 # System philosophy and architecture
        │   ├── AnalyticsPage.jsx                 # Deep-dive traffic and protocol analytics
        │   ├── DemoLabPage.jsx                   # PCAP replay, generation & benchmarking lab
        │   ├── IncidentsPage.jsx                 # Incident response and alert management
        │   ├── LiveMonitoringPage.jsx            # Real-time throughput and telemetry
        │   ├── OverviewPage.jsx                  # Executive Threat Matrix & detector status
        │   └── TeamPage.jsx                      # Project credits and team info
        └── styles/                               # Modular CSS design system
            ├── base.css                          # Typography, buttons, and form styling
            ├── tokens.css                        # CSS color and spacing variables
            └── ...                               # Individual page stylesheets
```

---

## 2. Explanation of Important Directories

### `alerts/`
Responsible for the persistence, query, deduplication, and lifecycle progression of security alerts.
- **[alert_record.py](file:///d:/Projects/sentinelflow-ctd/alerts/alert_record.py):** Defines the `AlertRecord` dataclass, containing `alert_id`, `source_ip`, `attack_type`, `severity`, `confidence`, `first_seen`, `last_seen`, `status` (`ACTIVE`/`RESOLVED`), and supporting `reasons`.
- **[alert_manager.py](file:///d:/Projects/sentinelflow-ctd/alerts/alert_manager.py):** Prevents duplicate alerts by maintaining active incidents. Automatically resolves incidents if no further packets are observed for 300 seconds.
- **[alert_store.py](file:///d:/Projects/sentinelflow-ctd/alerts/alert_store.py):** Encapsulates SQL transactions. Connects to PostgreSQL using `psycopg 3` with native `JSONB` fields; falls back automatically to SQLite (`ctd_alerts.db`) if PostgreSQL is unavailable.

### `api/` & `api/routes/`
Contains the FastAPI REST web service.
- **[api/main.py](file:///d:/Projects/sentinelflow-ctd/api/main.py):** Application entry point on port 8000. Configures permissive CORS (`*`), mounts routers, and defines root health check endpoints (`/` and `/api/health`).
- **[api/routes/alerts.py](file:///d:/Projects/sentinelflow-ctd/api/routes/alerts.py):** Endpoints to query active alerts, query alert history, trigger attack simulations, and resolve or clear incidents.
- **[api/routes/metrics.py](file:///d:/Projects/sentinelflow-ctd/api/routes/metrics.py):** Serves the latest completed observation window and the 60-second rolling history.
- **[api/routes/pcap.py](file:///d:/Projects/sentinelflow-ctd/api/routes/pcap.py):** Manages PCAP files, triggers synthetic PCAP generation, executes replay benchmarks, and validates detection accuracy against ground truth.

### `collector/`
Responsible for physical network packet ingestion.
- **[packet_collector.py](file:///d:/Projects/sentinelflow-ctd/collector/packet_collector.py):** Sniffs live interfaces using Scapy's `sniff()`. Drives the global feature trackers and runs the `background_flusher` thread.
- **[pcap_replay_collector.py](file:///d:/Projects/sentinelflow-ctd/collector/pcap_replay_collector.py):** Ingests offline `.pcap` files using `PcapReader`. Shifts packet timestamps relative to wall-clock time and outputs sustained throughput benchmarks (pps, Mbps, flows/sec).

### `detectors/`
Contains all threat detection logic and correlation algorithms.
- **Heuristic Detectors:** Individual modules targeting specific threat classes (`scan_detector.py`, `syn_flood_detector.py`, `exfiltration_detector.py`, `beacon_detector.py`, `dga_detector.py`, `tls_detector.py`).
- **[detector_engine.py](file:///d:/Projects/sentinelflow-ctd/detectors/detector_engine.py):** Orchestrates detector execution across all sources observed in the completed window.
- **[incident_correlator.py](file:///d:/Projects/sentinelflow-ctd/detectors/incident_correlator.py):** Synthesizes raw detector signals, collapses overlapping attacks (e.g. scan + SYN flood), and reassigns victim-side responder ML anomalies to the offending initiator as impact evidence.

### `features/`
Extracts streaming metrics across multiple time horizons.
- **[window.py](file:///d:/Projects/sentinelflow-ctd/features/window.py):** Governs the 1.0-second fixed observation clock.
- **[behavior_window.py](file:///d:/Projects/sentinelflow-ctd/features/behavior_window.py):** Rolling 10-second window for data exfiltration analysis.
- **[beacon_tracker.py](file:///d:/Projects/sentinelflow-ctd/features/beacon_tracker.py):** Rolling 300-second window computing inter-arrival Coefficient of Variation ($CV$).
- **[dns_tracker.py](file:///d:/Projects/sentinelflow-ctd/features/dns_tracker.py):** Rolling 30-second window computing Shannon entropy on domain names.
- **[tls_parser.py](file:///d:/Projects/sentinelflow-ctd/features/tls_parser.py) & [tls_tracker.py](file:///d:/Projects/sentinelflow-ctd/features/tls_tracker.py):** Zero-decryption TLS ClientHello parser, GREASE filter, and JA3 fingerprint generator.

### `flow/`
- **[flow_engine.py](file:///d:/Projects/sentinelflow-ctd/flow/flow_engine.py):** Tracks bidirectional 5-tuple sessions and evaluates TCP handshake flags (`S` vs `SA`) to determine communication roles (`initiator_ip` vs `responder_ip`).

### `inference/`
Houses the machine learning anomaly detection subsystem.
- **[feature_schema.py](file:///d:/Projects/sentinelflow-ctd/inference/feature_schema.py):** Defines the fixed 16-dimensional feature vector and baseline imputation values.
- **[ml_detector.py](file:///d:/Projects/sentinelflow-ctd/inference/ml_detector.py):** Loads `model.joblib` and `feature_stats.json`. Scores feature vectors and produces human-readable z-score explanations.
- **[train_model_from_pcap.py](file:///d:/Projects/sentinelflow-ctd/inference/train_model_from_pcap.py):** Trains the Isolation Forest model on benign PCAP captures using the exact same streaming feature pipeline.

### `scripts/`
- **[generate_synthetic_traffic.py](file:///d:/Projects/sentinelflow-ctd/scripts/generate_synthetic_traffic.py):** Builds realistic multi-host gateway PCAPs with benign traffic and embedded attacks.
- **[validate_detections.py](file:///d:/Projects/sentinelflow-ctd/scripts/validate_detections.py):** Compares database alerts against a ground-truth JSON manifest, reporting true positives, false positives, false negatives, precision, recall, and F1.

### `telemetry/`
- **[live_metrics.py](file:///d:/Projects/sentinelflow-ctd/telemetry/live_metrics.py):** Persists rolling 60-second throughput metrics (pps, Mbps, flows/sec) to PostgreSQL or SQLite.

---

## 3. Application Entry Points

| Role | File Path | Startup Command |
| :--- | :--- | :--- |
| **Backend API Service** | [api/main.py](file:///d:/Projects/sentinelflow-ctd/api/main.py) | `uvicorn api.main:app --reload --port 8000` |
| **PCAP Replay Ingestion** | [collector/pcap_replay_collector.py](file:///d:/Projects/sentinelflow-ctd/collector/pcap_replay_collector.py) | `python -m collector.pcap_replay_collector demo.pcap --max-speed` |
| **Live Network Sniffer** | [collector/packet_collector.py](file:///d:/Projects/sentinelflow-ctd/collector/packet_collector.py) | `python -m collector.packet_collector <interface_name>` |
| **Frontend Web Client** | [frontend/src/main.jsx](file:///d:/Projects/sentinelflow-ctd/frontend/src/main.jsx) | `cd frontend && npm run dev` |

---

## 4. Ephemeral, Generated & Legacy Files

- **`ctd_alerts.db` / `ctd_metrics.db`:** SQLite database files automatically generated in the workspace root when PostgreSQL is not configured.
- **`demo.pcap` / `benign.pcap`:** PCAP captures generated by `scripts/generate_synthetic_traffic.py` for testing and evaluation.
- **`*.ground_truth.json`:** JSON label files mapping expected attacker IPs and attack types.
- **`frontend/src/styles/theme.css.legacy`:** Legacy stylesheet preserved for historical reference; modern styling is managed via `tokens.css` and modular page CSS.
- **`frontend/recovered1.css`:** Orphaned recovery artifact from a prior local editor session; not used by the application.
