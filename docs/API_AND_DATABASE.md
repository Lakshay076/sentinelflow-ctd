# SentinelFlow-CTD: API & Database Reference

## 1. REST API Architecture

The SentinelFlow-CTD API is built using **FastAPI** and served by **Uvicorn**.

### Architectural Standards
- **Base URL:** `http://localhost:8000` (or configured host IP)
- **Content Type:** `application/json` for all requests and responses
- **CORS Policy:** Completely open (`allow_origins=["*"]`) for development flexibility across different frontend ports.
- **Authentication:** None currently required. All endpoints are accessible directly.
- **Interactive Documentation:** Available at `http://localhost:8000/docs` (Swagger UI) and `http://localhost:8000/redoc` (ReDoc).

---

## 2. Complete REST Endpoint Reference

### System & Health Endpoints

#### 1. Root Service Information
- **Endpoint:** `GET /`
- **Description:** Returns basic engine status and detection mode.
- **Response (200 OK):**
  ```json
  {
    "name": "CTD",
    "description": "Cyber Threat Detection",
    "status": "running",
    "mode": "detection-only"
  }
  ```

#### 2. Health Check
- **Endpoint:** `GET /api/health`
- **Description:** Readiness probe used by frontend polling loops.
- **Response (200 OK):**
  ```json
  {
    "status": "healthy",
    "service": "ctd-api"
  }
  ```

#### 3. Incident Statistics
- **Endpoint:** `GET /api/stats`
- **Description:** Returns total, active, and resolved alert counts, plus a breakdown by attack category.
- **Response (200 OK):**
  ```json
  {
    "total_alerts": 14,
    "active_alerts": 2,
    "resolved_alerts": 12,
    "attack_types": {
      "PORT_SCAN": 3,
      "SYN_FLOOD": 4,
      "DATA_EXFILTRATION": 2,
      "C2_BEACONING": 2,
      "DGA_DNS_TUNNELLING": 1,
      "TLS_METADATA_ANOMALY": 1,
      "ML_ANOMALY": 1
    }
  }
  ```

---

### Alert Management Endpoints (`/api/alerts`)

#### 4. List Active Alerts
- **Endpoint:** `GET /api/alerts/active`
- **Description:** Returns all security alerts currently in `ACTIVE` state.
- **Response (200 OK):**
  ```json
  {
    "count": 1,
    "alerts": [
      {
        "alert_id": 1,
        "source_ip": "10.0.0.50",
        "attack_type": "PORT_SCAN",
        "severity": "HIGH",
        "confidence": 1.0,
        "first_seen": 1700650000.123,
        "last_seen": 1700650001.456,
        "resolved_at": null,
        "status": "ACTIVE",
        "event_count": 3,
        "duration": 1.333,
        "reasons": [
          "high destination-port diversity (25 ports)",
          "multiple connection attempts (25 flows)",
          "high SYN ratio (0.95)",
          "high connection rate (18.75 flows/sec)"
        ],
        "initiator_ip": "10.0.0.50",
        "responder_ips": ["203.0.113.5"],
        "related_flows": []
      }
    ]
  }
  ```

#### 5. List Alert History
- **Endpoint:** `GET /api/alerts/history`
- **Description:** Returns all alerts recorded in the database, including both `ACTIVE` and `RESOLVED` incidents.
- **Response (200 OK):** Same schema as `/api/alerts/active`.

#### 6. Get Alert by ID
- **Endpoint:** `GET /api/alerts/{alert_id}`
- **Description:** Fetches full details for a single alert record.
- **Response (200 OK):** Single `AlertRecord` object. Returns `404 Not Found` if `alert_id` does not exist.

#### 7. Simulate Attack
- **Endpoint:** `POST /api/alerts/simulate/{attack_type}` (or `POST /api/alerts/simulate`)
- **Query / Path Parameter:** `attack_type` (e.g., `PORT_SCAN`, `SYN_FLOOD`, `DATA_EXFILTRATION`, `C2_BEACONING`, `DGA_DNS_TUNNELLING`, `TLS_METADATA_ANOMALY`)
- **Query Parameter (Optional):** `source_ip` (defaults to `10.10.10.10`)
- **Description:** Executes an in-memory Scapy packet sequence through the detection pipeline to generate a genuine alert for UI evaluation.
- **Response (200 OK):**
  ```json
  {
    "status": "completed",
    "attack_type": "PORT_SCAN",
    "source_ip": "10.10.10.10",
    "target_ip": "10.10.10.20",
    "packets_sent": 25,
    "detected": true,
    "alert": {
      "alert_id": 2,
      "source_ip": "10.10.10.10",
      "attack_type": "PORT_SCAN",
      "severity": "HIGH",
      "confidence": 1.0,
      "status": "ACTIVE",
      "reasons": [...]
    }
  }
  ```

#### 8. Resolve All Active Alerts
- **Endpoint:** `POST /api/alerts/resolve-all`
- **Description:** Sets `status = 'RESOLVED'` and stamps `resolved_at = time.time()` for all currently active alerts.
- **Response (200 OK):**
  ```json
  {
    "status": "success",
    "resolved_count": 3
  }
  ```

#### 9. Clear Alert History
- **Endpoint:** `POST /api/alerts/clear-history` (or `DELETE /api/alerts/history`)
- **Description:** Deletes all `RESOLVED` alerts from the database.
- **Response (200 OK):**
  ```json
  {
    "status": "success",
    "cleared_count": 5
  }
  ```

#### 10. Clear All Alerts
- **Endpoint:** `POST /api/alerts/clear-all` (or `DELETE /api/alerts/all`)
- **Description:** Truncates/deletes all alerts from the database.
- **Response (200 OK):**
  ```json
  {
    "status": "success",
    "cleared_count": 8
  }
  ```

---

### Live Telemetry Endpoints (`/api/metrics`)

#### 11. Get Live Telemetry
- **Endpoint:** `GET /api/metrics/live`
- **Description:** Returns the latest 1-second completed window telemetry along with the rolling 60-second time series.
- **Response (200 OK):**
  ```json
  {
    "status": "ok",
    "latest": {
      "timestamp": 1700650050.0,
      "window_duration": 1.0,
      "packets": 1250,
      "bytes": 985200,
      "packets_per_second": 1250.0,
      "bytes_per_second": 985200.0,
      "mbps": 7.881,
      "flows_per_second": 85.0,
      "active_flows": 85,
      "unique_sources": 24,
      "unique_destinations": 35,
      "tcp_packets": 1100,
      "udp_packets": 150,
      "icmp_packets": 0,
      "tcp_syn": 90,
      "tcp_ack": 950,
      "tcp_rst": 5
    },
    "history": [ ... ]
  }
  ```

---

### PCAP Replay & Benchmarking Endpoints (`/api/pcap`)

#### 12. List PCAP Files
- **Endpoint:** `GET /api/pcap/files`
- **Description:** Scans the repository root and `data/` for available `.pcap`/`.pcapng` files and companion ground-truth manifests.
- **Response (200 OK):**
  ```json
  {
    "files": [
      {
        "filename": "demo.pcap",
        "size_bytes": 726928,
        "size_mb": 0.69,
        "modified_at": 1700650000.0,
        "has_ground_truth": true,
        "ground_truth_file": "demo.pcap.ground_truth.json"
      }
    ]
  }
  ```

#### 13. Generate Synthetic PCAP
- **Endpoint:** `POST /api/pcap/generate`
- **Request Body:**
  ```json
  {
    "out": "demo.pcap",
    "attacks": ["scan", "syn_flood", "exfil", "beacon", "dga", "tls"]
  }
  ```
- **Description:** Generates synthetic multi-host gateway traffic and writes the `.pcap` capture along with `.ground_truth.json`.
- **Response (200 OK):**
  ```json
  {
    "status": "success",
    "pcap_file": "demo.pcap",
    "ground_truth_file": "demo.pcap.ground_truth.json",
    "packet_count": 850,
    "internal_hosts": 20,
    "external_hosts": 39,
    "attacks_included": ["scan", "syn_flood", "exfil", "beacon", "dga", "tls"]
  }
  ```

#### 14. Replay PCAP
- **Endpoint:** `POST /api/pcap/replay`
- **Request Body:**
  ```json
  {
    "pcap_file": "demo.pcap",
    "speed": 1.0,
    "max_speed": true
  }
  ```
- **Description:** Feeds the PCAP through the detection pipeline and returns throughput benchmark metrics.
- **Response (200 OK):**
  ```json
  {
    "status": "success",
    "benchmark": {
      "status": "completed",
      "pcap_file": "demo.pcap",
      "packet_count": 850,
      "byte_count": 726928,
      "wall_elapsed": 0.068,
      "sustained_pps": 12450.2,
      "sustained_mbps": 42.15,
      "flows_seen": 124,
      "flow_rate": 1771.4,
      "windows_evaluated": 1,
      "alert_events": 7,
      "last_run": 1700650100.0
    }
  }
  ```

#### 15. Validate Detection Accuracy
- **Endpoint:** `GET /api/pcap/validate?manifest=demo.pcap.ground_truth.json`
- **Description:** Evaluates database alert accuracy against ground-truth labels.
- **Response (200 OK):**
  ```json
  {
    "status": "success",
    "report": {
      "ground_truth_file": "demo.pcap.ground_truth.json",
      "total_alerts": 7,
      "true_positives": 6,
      "false_negatives": 0,
      "false_positives": 0,
      "precision": 1.0,
      "recall": 1.0,
      "f1": 1.0
    }
  }
  ```

---

## 3. Database Architecture & Schema

SentinelFlow-CTD employs a dual-database architecture managed by `alerts/alert_store.py` and `telemetry/live_metrics.py`.

```
                   Application Ingestion & API
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
      PostgreSQL Available?          Fallback / Local Dev
               │                               │
               ▼                               ▼
    PostgreSQL with JSONB               Local SQLite 3
   (Production Deployment)           (ctd_alerts.db / ctd_metrics.db)
```

### Table 1: `alerts`

#### PostgreSQL Schema (DDL)
```sql
CREATE TABLE IF NOT EXISTS alerts (
    alert_id       SERIAL PRIMARY KEY,
    source_ip      TEXT NOT NULL,
    attack_type    TEXT NOT NULL,
    severity       TEXT NOT NULL,
    confidence     REAL NOT NULL,
    first_seen     REAL NOT NULL,
    last_seen      REAL NOT NULL,
    resolved_at    REAL,
    status         TEXT NOT NULL DEFAULT 'ACTIVE',
    event_count    INTEGER NOT NULL DEFAULT 1,
    reasons        JSONB NOT NULL,
    initiator_ip   TEXT,
    responder_ips  JSONB,
    related_flows  JSONB,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### SQLite Schema (DDL)
```sql
CREATE TABLE IF NOT EXISTS alerts (
    alert_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip      TEXT NOT NULL,
    attack_type    TEXT NOT NULL,
    severity       TEXT NOT NULL,
    confidence     REAL NOT NULL,
    first_seen     REAL NOT NULL,
    last_seen      REAL NOT NULL,
    resolved_at    REAL,
    status         TEXT NOT NULL DEFAULT 'ACTIVE',
    event_count    INTEGER NOT NULL DEFAULT 1,
    reasons        TEXT NOT NULL,       -- Serialized JSON string
    initiator_ip   TEXT,
    responder_ips  TEXT,                -- Serialized JSON string
    related_flows  TEXT,                -- Serialized JSON string
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Column Details
- `alert_id`: Unique integer identifier.
- `source_ip`: IP address identified as the source of the anomalous behavior.
- `attack_type`: Categorical identifier (`PORT_SCAN`, `SYN_FLOOD`, `DATA_EXFILTRATION`, `C2_BEACONING`, `DGA_DNS_TUNNELLING`, `TLS_METADATA_ANOMALY`, `ML_ANOMALY`).
- `severity`: Severity rating (`LOW`, `MEDIUM`, `HIGH`).
- `confidence`: Confidence score from $0.0$ to $1.0$.
- `first_seen` / `last_seen`: Unix epoch timestamps.
- `resolved_at`: Unix epoch timestamp when marked resolved (or `NULL` if active).
- `status`: Lifecycle state (`ACTIVE` or `RESOLVED`).
- `event_count`: Number of times this threat pattern re-fired across observation windows.
- `reasons`: Array of human-readable evidence strings detailing threshold breaches.
- `initiator_ip`: Connection initiator identified via TCP handshake flags.
- `responder_ips`: Array of target IPs contacted by this source.
- `related_flows`: Detailed 5-tuple flow records observed during the incident.

---

### Table 2: `live_metrics`

#### PostgreSQL Schema (DDL)
```sql
CREATE TABLE IF NOT EXISTS live_metrics (
    id                 SERIAL PRIMARY KEY,
    timestamp          DOUBLE PRECISION NOT NULL,
    window_duration    DOUBLE PRECISION,
    packets            INTEGER,
    bytes              INTEGER,
    packets_per_second DOUBLE PRECISION,
    bytes_per_second   DOUBLE PRECISION,
    mbps               DOUBLE PRECISION,
    flows_per_second   DOUBLE PRECISION,
    active_flows       INTEGER,
    unique_sources     INTEGER,
    unique_destinations INTEGER,
    tcp_packets        INTEGER,
    udp_packets        INTEGER,
    icmp_packets       INTEGER,
    tcp_syn            INTEGER,
    tcp_ack            INTEGER,
    tcp_rst            INTEGER
);
```

#### SQLite Schema (DDL)
```sql
CREATE TABLE IF NOT EXISTS live_metrics (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp          REAL NOT NULL,
    window_duration    REAL,
    packets            INTEGER,
    bytes              INTEGER,
    packets_per_second REAL,
    bytes_per_second   REAL,
    mbps               REAL,
    flows_per_second   REAL,
    active_flows       INTEGER,
    unique_sources     INTEGER,
    unique_destinations INTEGER,
    tcp_packets        INTEGER,
    udp_packets        INTEGER,
    icmp_packets       INTEGER,
    tcp_syn            INTEGER,
    tcp_ack            INTEGER,
    tcp_rst            INTEGER
);
```

#### Automatic Rolling Window Pruning
To prevent unbounded database file growth, `LiveMetricsStore.add_window()` executes an automatic pruning query after every insert:
```sql
DELETE FROM live_metrics
WHERE id NOT IN (
    SELECT id FROM live_metrics
    ORDER BY timestamp DESC, id DESC
    LIMIT 60
);
```
This guarantees the table always contains exactly the most recent 60 completed observation windows.
