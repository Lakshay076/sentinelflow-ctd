# SentinelFlow-CTD — Supervised Threat Classification

## Overview

SentinelFlow-CTD uses a **two-stage detection and triage architecture**:

1. **Stage 1 — Existing Detection & Unsupervised Anomaly Detection**
   - Rule-based detectors (`PORT_SCAN`, `SYN_FLOOD`, `UDP_FLOOD`, `DISTRIBUTED_UDP_FLOOD`, `DATA_EXFILTRATION`, `C2_BEACONING`, `DGA_DNS_TUNNELLING`, `TLS_METADATA_ANOMALY`) and the **Isolation Forest** (`ML_ANOMALY`) evaluate 1-second traffic windows and per-source behavior.
   - Stage 1 remains completely authoritative and unchanged.

2. **Stage 2 — Supervised Threat Classification (`ThreatClassifier`)**
   - Whenever Stage 1 raises an `ML_ANOMALY` alert for a source IP, the active bidirectional flows initiated by or involving that source (`LiveFlowTracker`) are passed to a trained **Random Forest** classifier (`supervised/classifier.py`).
   - The classifier predicts a likely threat category, a confidence score, top alternative predictions, and supporting flow features.
   - If confidence is below the threshold (`0.50`), the prediction safely falls back to `UNCLASSIFIED`.

---

## Key Architectural Decisions

### 1. Why Stage 2 Only Runs on `ML_ANOMALY` (Not Rule-Based Alerts)
- Rule-based detectors already identify specific SentinelFlow attack signatures (such as `DATA_EXFILTRATION` or `DGA_DNS_TUNNELLING`) using domain-specific heuristics.
- Running a CIC-IDS2017-trained flow classifier on custom rule-based alerts would risk contradicting them (e.g., labeling synthetic exfiltration as `BENIGN`).
- Restricting Stage 2 classification to `ML_ANOMALY` keeps rule-based alerts clean while giving operators actionable threat-type context on unsupervised anomalies.

### 2. Flow-Level Classification (Not Packet-Level)
- The CIC-IDS2017 dataset defines **77 bidirectional flow statistical features** (inter-arrival times in microseconds, packet length moments, TCP flag counts, header lengths, active/idle periods).
- `LiveFlowTracker` (`supervised/feature_extractor.py`) maintains per-flow accumulators in real time inside `collector/packet_collector.py` and only computes the 77-feature vector when an `ML_ANOMALY` is triggered. This keeps live packet ingestion fast.

### 3. Fail-Safe, Non-Blocking Design
- If model artifacts are missing (`MODEL_UNAVAILABLE`), no candidate flows exist (`NO_CANDIDATE_FLOWS`), or inference raises an exception (`ERROR`), the `ML_ANOMALY` alert is **never suppressed**. It is still created, stored, and shown on the dashboard.

### 4. Separation of Training & Inference
- **Offline training** lives in `supervised/dataset_loader.py`, `supervised/splitter.py`, `supervised/preprocessing.py`, `supervised/train.py`, `supervised/evaluate.py`, and `supervised/run_training.py`.
- **Production inference** uses `supervised/classifier.py` and `supervised/predict.py`, loading immutable versioned bundles from `supervised/artifacts/<version>/` (referenced via `supervised/artifacts/latest`).

---

## Dataset & Label Mapping (CIC-IDS2017)

- **Source**: `data/cic_ids2017/raw/MachineLearningCSV/` (8 CSV files; excluded from Git via `.gitignore`).
- **Cleaning**:
  - 2,830,743 raw rows loaded in chunks.
  - 256,684 exact duplicate rows removed, leaving **2,574,059** clean rows.
  - Duplicate column `Fwd Header Length.1` dropped; **77** features retained.
- **Temporal Split**:
  - `per_label_capture_order_holdout` (80% train = 2,059,247 rows; 20% test = 491,914 rows, with cross-split duplicates removed from test).
  - Preprocessing (`InfToNaN` -> `SimpleImputer(median)` -> `RobustScaler`) is fit **only** on training data.
- **Target Categories (8 trained + 1 runtime fallback)**:
  - `BENIGN`
  - `DOS_DDOS` (DoS Hulk, GoldenEye, slowloris, Slowhttptest, DDoS)
  - `RECONNAISSANCE` (PortScan)
  - `BRUTE_FORCE` (FTP-Patator, SSH-Patator)
  - `WEB_ATTACK` (Brute Force, XSS, SQL Injection)
  - `BOTNET_C2` (Bot)
  - `INFILTRATION` (Infiltration)
  - `OTHER_ATTACK` (Heartbleed)
  - `UNCLASSIFIED` (runtime fallback when confidence < `0.50`)

### Baseline Evaluation (`supervised/artifacts/v2`)
Measured on the held-out 20% test split (491,914 rows):
- **Accuracy**: `98.92%`
- **Balanced Accuracy**: `60.56%`
- **Macro F1**: `0.6142`
- **Weighted F1**: `0.9895`

---

## API & Dashboard Integration

- **Alert Payload Fields**: Every alert in `/api/alerts/active`, `/api/alerts/history`, and `/api/alerts/{alert_id}` includes:
  - `predicted_threat`, `threat_confidence`, `alternative_predictions`, `classification_status`, `model_version`, `feature_schema_version`, `supporting_features`.
- **Filtering**: `/api/alerts/active?predicted_threat=DOS_DDOS` and `/api/alerts/history?predicted_threat=...`.
- **Classifier Status**: `GET /api/alerts/classifier/status` returns live model availability, version, schema version, threshold, categories, and saved evaluation metrics.
- **Stats**: `GET /api/stats` includes `predicted_threats`, `classifier_available`, and `classifier_model_version`.
- **Dashboard UI**:
  - `AlertCard` displays an AI triage badge when classification metadata is present.
  - `IncidentDrawer` shows a **Supervised Threat Classification** section with confidence bar, alternative predictions, model/schema version, and top supporting flow features.
  - `IncidentsPage` history table shows the `AI: <category>` triage label inline.
