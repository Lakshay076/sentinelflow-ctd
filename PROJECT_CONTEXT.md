# Project Context

## 1. Project Overview

* **Project name**: SentinelFlow-CTD (Cyber Threat Detection Engine)
* **Purpose**: A real-time, passive network cyber threat detection and monitoring system built for high-throughput gateway observation and SIH-aligned security challenges.
* **Main functionality**: 
  - Analyzes PCAP files or live network traffic (via Scapy).
  - Extracts network features into streaming windows (flow rates, SYN ratios, outbound ratios, DNS/TLS metadata).
  - Runs a hybrid detection pipeline: 5 rule-based specific detectors (Port Scan, SYN flood, Data Exfiltration, C2 Beaconing, DGA DNS Tunnelling, TLS Metadata) and 1 Unsupervised ML anomaly detector (Isolation Forest).
  - Provides a FastAPI backend and React/Vite frontend for live monitoring, alerts, and PCAP replay benchmarking.
* **Current project status**: Active development/testing. Functional local dev environment with scripts to generate synthetic traffic, train ML models, and validate detections against a ground truth manifest.

## 2. Technology Stack

* **Programming language**: Python (Backend / Collector / ML), JavaScript/TypeScript (Frontend)
* **Python version**: 3.x (Assumed 3.9+ based on dependencies like `psycopg==3.3.4` and FastAPI)
* **Framework**: FastAPI (Backend API), React with Vite (Frontend)
* **Libraries**: `scapy`, `scikit-learn`, `joblib`, `numpy`, `pandas`, `psycopg`
* **Database**: PostgreSQL (primary) with automatic cross-process SQLite fallback (`ctd_alerts.db`).
* **AI/ML technologies**: Unsupervised Machine Learning via Isolation Forest (`scikit-learn`) using z-score normalization for explainability.
* **Frontend/backend components**: 
  - Frontend: React + Vite + Lucide Icons.
  - Backend: FastAPI (uvicorn).
  - Collector: Independent Python background scripts running Scapy.

## 3. Project Architecture

The architecture consists of a passive packet sniffer/collector (which runs as a separate script), which feeds traffic features into a detection engine, which writes to an Alert Store. The FastAPI backend serves these alerts to the Frontend client.

```text
       Live Network (en0) / PCAP File
                  ↓
       Collector (Scapy Ingest)
                  ↓
 Feature Extraction Pipeline (Flow, Windows, Trackers)
                  ↓
   Detection Engine (Rule-based + ML Model)
                  ↓
 Alert Store (PostgreSQL / SQLite Fallback)
                  ↓
          FastAPI (Backend)
                  ↓
        React / Vite (Frontend Client)
```

## 4. Folder Structure

* `api/`: FastAPI application code and routes (`main.py`, `routes/`).
* `alerts/`: Database interaction layer and Alert object models (`alert_store.py`).
* `collector/`: Scapy-based ingestion scripts for PCAP (`pcap_replay_collector.py`) and live interfaces (`packet_collector.py`).
* `detectors/`: Rule-based detection logic.
* `features/`: Feature extraction modules (Flow tracker, DNS tracker, TLS JA3, behavior windows).
* `flow/`: Lower-level connection flow tracking.
* `frontend/`: The React / Vite user interface codebase.
* `inference/`: Machine learning files (`ml_detector.py`, `train_model_from_pcap.py`, `model.joblib`, `feature_stats.json`).
* `scripts/`: Utilities to generate synthetic traffic (`generate_synthetic_traffic.py`) and validate results.
* `tests/`: Integration and unit tests (`test_all_attacks.py`, `test_api_endpoints.py`).
* `telemetry/`: Real-time system and throughput metrics.

## 5. Application Entry Points

* **Main files**: `api/main.py` (FastAPI), `collector/pcap_replay_collector.py` (PCAP tool), `collector/packet_collector.py` (Live sniffing tool).
* **Startup commands (Dev)**:
  - Backend: `uvicorn api.main:app --reload --port 8000`
  - Frontend: `npm run dev` (inside `frontend/` directory)
  - PCAP Replay: `python -m collector.pcap_replay_collector demo.pcap --max-speed`
  - Live Sniffing: `sudo python -m collector.packet_collector <interface_name>`
* **Development server**: Uvicorn (port 8000), Vite (port 5173).
* **Production server**: None explicitly configured yet (would typically use Gunicorn+Uvicorn and Nginx).

## 6. API Documentation

* **GET `/`**: Root health check. Returns basic service information.
* **GET `/api/health`**: Simple health check endpoint.
* **GET `/api/stats`**: Returns summary counts of total, active, and resolved alerts, plus a breakdown by attack type.
* **GET `/api/alerts/active`**: Fetches all currently active alerts.
* **GET `/api/alerts/history`**: Fetches the full history of alerts.
* **POST `/api/alerts/simulate/{attack_type}`**: Simulates an alert being triggered. `attack_type` can be PORT_SCAN, SYN_FLOOD, DATA_EXFILTRATION, C2_BEACONING, DGA_DNS_TUNNELLING, TLS_METADATA_ANOMALY, or ML_ANOMALY.
* **POST `/api/alerts/resolve-all`**: Marks all active alerts as resolved.
* **POST `/api/alerts/clear-history`** (or **DELETE `/api/alerts/history`**): Deletes all resolved alerts.
* **POST `/api/alerts/clear-all`** (or **DELETE `/api/alerts/all`**): Truncates the alerts table.
* **GET `/api/alerts/{alert_id}`**: Retrieves a specific alert by ID.
* **GET `/api/pcap/files`**: Lists available PCAP files and their ground-truth manifests.
* **POST `/api/pcap/generate`**: Generates a synthetic multi-host gateway traffic capture with ground-truth labels.
* **POST `/api/pcap/replay`**: Replays a PCAP file through the detection engine and returns real-time benchmark metrics.
* **GET `/api/pcap/benchmark`**: Returns the latest throughput benchmark metrics.
* **GET `/api/pcap/validate`**: Evaluates detection accuracy against ground truth.
* **GET `/api/metrics/live`**: Returns the latest live telemetry window and rolling 60-second history.

*No authentication is currently required for any endpoint.*

## 7. Environment Variables

* `DATABASE_URL`: The connection string for the PostgreSQL database (e.g. `DATABASE_URL=<your_postgres_url>`). Located in `.env`. If invalid or unavailable, the system safely falls back to SQLite (`ctd_alerts.db`).
* `CTD_INTERFACE`: Used by `collector/packet_collector.py` to specify the live network interface to sniff (e.g., `eth0` or `en0`).

## 8. Database

* **Database type**: PostgreSQL (via `psycopg`) with an automatic fallback to SQLite 3.
* **Models/tables/collections**: Single table `alerts`.
* **Important relationships**: None, it is a single flat table for incident logging.
* **Connection method**: Checked at startup in `AlertStore`. If PostgreSQL is reachable, it uses `psycopg`. Otherwise, it falls back to a local `ctd_alerts.db` SQLite file.
* **Required configuration**: Provide a valid `DATABASE_URL` if PostgreSQL is desired.

## 9. AI/ML Pipeline

* **Models**: Isolation Forest.
* **Model architecture**: Unsupervised ensemble algorithm for anomaly detection.
* **Input format**: 16-dimensional feature vector containing numerical aggregates (e.g., flows_per_second, syn_packet_ratio, outbound_inbound_ratio).
* **Output format**: +1 (Normal) or -1 (Anomaly), mapped to an anomaly score/confidence and mapped back to z-scores for natural language explanations.
* **Feature extraction**: Uses `scapy` to read packets, groups them into 1-second and larger temporal windows per source IP. Features are processed identically in training and live inference.
* **Inference process**: The `ml_detector.py` loads `model.joblib` and `feature_stats.json`. Evaluates the vector and checks if the prediction is -1 with a raw score < -0.04.
* **Model files**: `inference/model.joblib` (trained weights) and `inference/feature_stats.json` (mean/std for z-score scaling).
* **Required libraries**: `scikit-learn`, `joblib`, `numpy`.
* **CPU/GPU requirements**: Runs on CPU (Isolation Forest is lightweight and doesn't require a GPU).

## 10. Important Configuration

* **Ports**: Backend API on `8000`, Frontend on `5173`.
* **Host**: Development binds to localhost (`127.0.0.1`).
* **CORS**: Completely open (`allow_origins=["*"]`).
* **File paths**: 
  - SQLite Database: `ctd_alerts.db` at project root.
  - PCAP Generation: Written directly to project root (e.g., `demo.pcap`).
  - ML Model Path: Hardcoded relative to the `inference` directory.

## 11. Local Development

1. Create a virtual environment: `python3 -m venv .venv`
2. Activate environment: `source .venv/bin/activate` (or `.venv\Scripts\activate` on Windows)
3. Install dependencies: `pip install -r requirements.txt`
4. Configure `.env`: `cp .env.example .env` and edit `DATABASE_URL` if using Postgres.
5. Start backend API: `uvicorn api.main:app --reload --port 8000`
6. Start frontend client: `cd frontend && npm install && npm run dev`
7. Optional: Run tests via `python -m tests.test_all_attacks`
8. Optional: Replay traffic `python -m collector.pcap_replay_collector demo.pcap --max-speed`

## 12. Production Deployment

*Deployment configurations (Dockerfiles, systemd, etc.) do not currently exist.*
When deploying, the following will be required:

* **Server requirements**: Linux server (Ubuntu/Debian recommended).
* **Python requirements**: Python 3.9+.
* **System dependencies**: `libpcap-dev` (for Scapy packet sniffing if running live). Node.js for building the frontend.
* **Process management**: Supervisor or Systemd to run the backend (`gunicorn` + `uvicorn` workers) AND a separate persistent daemon for the Collector.
* **Reverse proxy**: Nginx to serve the static frontend bundle, proxy API requests to port 8000.
* **Database**: Managed PostgreSQL instance is highly recommended instead of relying on the SQLite fallback (especially to prevent DB lock issues with concurrent collector and API processes).
* **HTTPS**: SSL/TLS certificate via Let's Encrypt.
* **Security**: Update FastAPI CORS config and restrict API endpoints.

## 13. Security

* **Authentication**: None. The API is entirely open.
* **Authorization**: None.
* **CORS**: `allow_origins=["*"]` (Highly permissive).
* **Exposed ports**: 8000, 5173 (if bound to 0.0.0.0).
* **Live Sniffing Risk**: Running `packet_collector.py` requires `root/sudo` privileges, which creates a large attack surface if the Python application were compromised.
* **Secrets**: `DATABASE_URL` is managed via `.env`.

## 14. Known Issues

* **CORS Configuration**: Wildcard CORS configuration is dangerous for production deployments.
* **No Authentication**: The API has no auth, meaning anyone can view or simulate alerts.
* **Database Concurrency**: The automatic fallback to SQLite can cause `database is locked` errors if the Collector and the API try to write/read heavily at the same time.
* **Missing Deployment Assets**: No Dockerfile, docker-compose, or production runner scripts are included.
* **Scapy Throughput Limitations**: `scapy` is notoriously slow for high-throughput packet processing in Python (often capping at ~10-20k pps). While it has a "benchmark mode", it might not handle true enterprise gigabit loads without dropping packets.

## 15. Important Commands

* **Installation**: `pip install -r requirements.txt` and `npm install` (in frontend).
* **Running Backend**: `uvicorn api.main:app --reload --port 8000`
* **Running Frontend**: `npm run dev`
* **Generate Test PCAP**: `python -m scripts.generate_synthetic_traffic --out demo.pcap`
* **Run PCAP Collector**: `python -m collector.pcap_replay_collector demo.pcap --max-speed`
* **Run Live Collector**: `sudo python -m collector.packet_collector en0`
* **Train ML Model**: `python -m inference.train_model_from_pcap benign.pcap`
* **Run Verification Tests**: `python -m tests.test_all_attacks`

## 16. Future AI Instructions

When working on this project in the future:

1. Read PROJECT_CONTEXT.md before making changes.
2. Preserve the existing architecture unless explicitly asked to change it.
3. Do not modify production configuration without explaining the change.
4. Do not expose or commit secrets.
5. Check existing dependencies before adding new ones.
6. Follow the existing coding patterns.
7. Before making major architectural changes, explain the impact.
8. When fixing bugs, identify the root cause before changing code.
9. After making changes, explain which files were modified and why.
10. Update PROJECT_CONTEXT.md whenever the architecture, dependencies, API, deployment process, or important configuration changes.
