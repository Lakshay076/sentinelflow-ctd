# SentinelFlow-CTD: Setup & Installation Guide

## 1. System Prerequisites

Before running SentinelFlow-CTD, ensure your host environment meets the following requirements:

### Software Requirements
- **Operating System:** Windows 10/11, macOS (Intel/Apple Silicon), or Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+).
- **Python:** Version `3.9` through `3.12` (Python 3.10 or 3.11 recommended).
- **Node.js & npm:** Node.js version `18.x` or later, with `npm` version `9.x` or later.
- **Git:** Installed and available on system `PATH`.

### Network & Packet Capture Drivers
- **Windows:** 
  - Install **Npcap** ([npcap.com](https://npcap.com/)) with **"Install Npcap in WinPcap API-compatible Mode"** enabled. This is required if you plan to sniff live packets using `packet_collector.py`.
  - *Note:* If you are only replaying PCAP files (`pcap_replay_collector.py`) or using the web demo simulator, Npcap is **not** required.
- **Linux:**
  - Install standard packet capture headers:
    ```bash
    sudo apt-get update && sudo apt-get install -y libpcap-dev tcpdump
    ```
- **macOS:**
  - Standard Berkeley Packet Filter (`bpf`) devices are present by default. Root privileges (`sudo`) are required for live interface capture.

---

## 2. Step-by-Step Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-username/sentinelflow-ctd.git
cd sentinelflow-ctd
```

### Step 2: Configure the Python Backend Virtual Environment

#### On Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### On Linux / macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Install Frontend Dependencies
Open a second terminal window (or navigate into `frontend/`):
```bash
cd frontend
npm install
cd ..
```

---

## 3. Environment Configuration & Database Setup

SentinelFlow-CTD supports two database configurations:

### Option A: SQLite Fallback Mode (Recommended for Demos & Local Dev)
The system requires **zero database setup** by default. If no external database is configured, SentinelFlow-CTD automatically creates and manages local SQLite database files:
- `ctd_alerts.db`: Stores all active and resolved security incidents.
- `ctd_metrics.db`: Stores the rolling 60-second throughput telemetry.

To use SQLite mode:
1. Copy the sample environment file:
   ```bash
   cp .env.example .env
   ```
2. Leave `DATABASE_URL` commented out or with the default placeholder password. The system will detect this and safely initialize SQLite.

### Option B: PostgreSQL Setup (Production / Multi-User Mode)
If you wish to run a dedicated PostgreSQL instance:
1. Create a PostgreSQL database and user:
   ```sql
   CREATE USER ctd_user WITH PASSWORD 'your_secure_password';
   CREATE DATABASE ctd OWNER ctd_user;
   GRANT ALL PRIVILEGES ON DATABASE ctd TO ctd_user;
   ```
2. Configure `.env` in the project root:
   ```env
   DATABASE_URL=postgresql://ctd_user:your_secure_password@localhost:5432/ctd
   CTD_INTERFACE=en0
   ```
3. When the API or collector starts, it will automatically connect and create the necessary tables (`alerts` and `live_metrics`) with native `JSONB` support.

---

## 4. Running the Application

SentinelFlow-CTD consists of a backend API server, a frontend client, and packet ingestion workers.

### 1. Start the FastAPI Backend
From the repository root (with virtual environment active):
```bash
uvicorn api.main:app --reload --port 8000
```
- API Documentation (Swagger UI): **http://localhost:8000/docs**
- API Health Endpoint: **http://localhost:8000/api/health**

### 2. Start the Frontend Dashboard
From the `frontend/` directory:
```bash
cd frontend
npm run dev
```
- Open **http://localhost:5173** in your browser to view the SOC dashboard.

---

## 5. PCAP Ingestion, Benchmarking & Testing Workflows

Once the backend and frontend are running, use the following canonical workflows to evaluate detection and throughput:

### Workflow 1: Generate Synthetic Gateway Traffic
Builds a synthetic multi-host PCAP capture representing thousands of packets across internal hosts, external destinations, and embedded attack vectors:
```bash
python scripts/generate_synthetic_traffic.py --out demo.pcap
```
This generates `demo.pcap` and its companion ground-truth manifest `demo.pcap.ground_truth.json`.

### Workflow 2: Replay Traffic Through Streaming Pipeline (Benchmark Mode)
Replays `demo.pcap` through the complete 1-second sliding window detection engine at maximum possible execution speed:
```bash
python -m collector.pcap_replay_collector demo.pcap --max-speed
```
*Expected Output:*
```text
======================================================================
REPLAY COMPLETE -- THROUGHPUT BENCHMARK
======================================================================
Total packets processed : 850
Total bytes processed   : 726,928
Wall-clock duration     : 0.07 s
Sustained packet rate   : 12,450.2 packets/sec
Sustained throughput    : 42.15 Mbps
Total flows observed    : 124
Flow rate               : 1,771.4 flows/sec
Windows evaluated       : 1
Alert events generated  : 7
======================================================================
```

### Workflow 3: Validate Detection Accuracy Against Ground Truth
Compares actual database alerts against the expected ground-truth labels:
```bash
python scripts/validate_detections.py demo.pcap.ground_truth.json
```
*Expected Output:*
```text
========================================================================
CTD -- DETECTION VALIDATION REPORT
========================================================================
Attacker IP    Expected attack type     Result     Confidence
------------------------------------------------------------------------
10.0.0.50      PORT_SCAN                CAUGHT     1.00
10.0.0.51      SYN_FLOOD                CAUGHT     1.00
10.0.0.52      DATA_EXFILTRATION        CAUGHT     1.00
10.0.0.53      C2_BEACONING             CAUGHT     1.00
10.0.0.54      DGA_DNS_TUNNELLING       CAUGHT     1.00
10.0.0.55      TLS_METADATA_ANOMALY     CAUGHT     1.00
------------------------------------------------------------------------
Precision : 1.000 (100.0%)
Recall    : 1.000 (100.0%)
F1 Score  : 1.000
========================================================================
```

### Workflow 4: Retrain Machine Learning Isolation Forest Model
To retrain the ML outlier detector on a benign traffic baseline:
```bash
# 1. Generate benign-only baseline capture
python scripts/generate_synthetic_traffic.py --out benign.pcap --attacks

# 2. Train model using the live streaming feature pipeline
python -m inference.train_model_from_pcap benign.pcap
```
This updates `inference/model.joblib` and `inference/feature_stats.json`.

### Workflow 5: Run Automated Test Suites
```bash
# Test all 7 threat detectors against simulated feature profiles
python -m tests.test_all_attacks

# Test FastAPI endpoints and PCAP replay integration
python -m tests.test_api_endpoints
```

---

## 6. Live Interface Sniffing (Optional)

To monitor physical network interfaces in real time:

### Finding Your Interface Name
- **Windows:** Run `Get-NetAdapter` in PowerShell.
- **Linux:** Run `ip link show` or `ifconfig`.
- **macOS:** Run `ifconfig` (Wi-Fi is typically `en0`).

### Running Live Capture
```bash
# Specify interface as command argument:
python -m collector.packet_collector eth0

# Or configure via environment variable:
export CTD_INTERFACE=eth0
python -m collector.packet_collector
```
*(On Linux/macOS, prepend `sudo` if packet capture permissions are required).*

---

## 7. Troubleshooting & Common Setup Pitfalls

| Symptom | Root Cause | Solution |
| :--- | :--- | :--- |
| `sqlite3.OperationalError: database is locked` | High-concurrency conflict between the collector writing and the API reading SQLite simultaneously. | Re-run with PostgreSQL enabled in `.env` for production loads, or reduce replay rate multiplier (`--speed 1.0`). |
| `Scapy: Sniffing on Windows failed` | Npcap is missing or not installed in WinPcap compatibility mode. | Download and install Npcap from [npcap.com](https://npcap.com/). Ensure **"WinPcap API-compatible Mode"** is checked during setup. |
| `PermissionError: [Errno 1] Operation not permitted` | User lacks raw socket binding permissions to sniff live network interfaces. | Run terminal as Administrator (Windows) or execute with `sudo` (Linux/macOS). |
| `Failed to fetch CTD data` in web browser | FastAPI backend is not running, or frontend is pointing to the wrong port. | Verify backend is running on `http://127.0.0.1:8000`. If hosted remotely, set `VITE_API_BASE=http://your-server-ip:8000` in `frontend/.env`. |
| ML Detector warning: `No trained model found` | `inference/model.joblib` is missing. | Run `python -m inference.train_model_from_pcap benign.pcap` to build the model weights. |
