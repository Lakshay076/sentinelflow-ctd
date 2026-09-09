import { useEffect, useState } from "react";
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Server,
  Zap,
  Radio,
  Globe,
  Lock,
  BrainCircuit,
  UploadCloud,
  Play,
  RotateCcw,
  SlidersHorizontal,
  Trash2,
  FileCode,
  Gauge,
  CheckCircle2,
  XCircle,
  Cpu,
  Layers,
  Sparkles,
  Award,
} from "lucide-react";

import "./App.css";

// Dynamic API detection: defaults to same host on port 8000
const API_BASE =
  import.meta.env.VITE_API_BASE ||
  (typeof window !== "undefined" && window.location.hostname
    ? `http://${window.location.hostname}:8000`
    : "http://localhost:8000");

const DETECTORS_CONFIG = [
  {
    type: "PORT_SCAN",
    label: "Port Scanning",
    category: "Reconnaissance",
    icon: Server,
    color: "#3b82f6",
    description: "Detects rapid destination port and host fan-out scans.",
  },
  {
    type: "SYN_FLOOD",
    label: "SYN Flood",
    category: "Volumetric DDoS",
    icon: Zap,
    color: "#ef4444",
    description: "Detects abnormal surges of incomplete TCP SYN handshakes.",
  },
  {
    type: "DATA_EXFILTRATION",
    label: "Data Exfiltration",
    category: "Data Loss",
    icon: UploadCloud,
    color: "#f59e0b",
    description: "Flags high asymmetric outbound-to-inbound byte volume.",
  },
  {
    type: "C2_BEACONING",
    label: "C2 Beaconing",
    category: "Botnet / C2",
    icon: Radio,
    color: "#8b5cf6",
    description: "Identifies regular, periodic inter-arrival check-ins.",
  },
  {
    type: "DGA_DNS_TUNNELLING",
    label: "DGA / DNS Tunnel",
    category: "DNS Evasion",
    icon: Globe,
    color: "#06b6d4",
    description: "Flags high-entropy or oversized domain queries.",
  },
  {
    type: "TLS_METADATA_ANOMALY",
    label: "TLS Anomaly",
    category: "Encrypted Malware",
    icon: Lock,
    color: "#ec4899",
    description: "Inspects ClientHello metadata, JA3 hashes, and missing SNI.",
  },
  {
    type: "ML_ANOMALY",
    label: "ML Anomaly (AI)",
    category: "Unsupervised",
    icon: BrainCircuit,
    color: "#10b981",
    description: "Isolation Forest evaluating 16-dimensional feature vectors.",
  },
];

function App() {
  const [stats, setStats] = useState(null);
  const [activeAlerts, setActiveAlerts] = useState([]);
  const [history, setHistory] = useState([]);
  const [health, setHealth] = useState(false);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [simulating, setSimulating] = useState(null);
  const [filterType, setFilterType] = useState("ALL");
  const [showTestPanel, setShowTestPanel] = useState(true);

  // PCAP Ingest & Benchmark State
  const [pcapFiles, setPcapFiles] = useState([]);
  const [selectedPcap, setSelectedPcap] = useState("demo.pcap");
  const [replaySpeed, setReplaySpeed] = useState("max");
  const [benchmarkResult, setBenchmarkResult] = useState(null);
  const [validationReport, setValidationReport] = useState(null);
  const [isReplaying, setIsReplaying] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [pcapMessage, setPcapMessage] = useState(null);

  async function fetchData() {
    try {
      const [
        healthResponse,
        statsResponse,
        activeResponse,
        historyResponse,
        filesResponse,
        benchmarkResponse,
      ] = await Promise.all([
        fetch(`${API_BASE}/api/health`),
        fetch(`${API_BASE}/api/stats`),
        fetch(`${API_BASE}/api/alerts/active`),
        fetch(`${API_BASE}/api/alerts/history`),
        fetch(`${API_BASE}/api/pcap/files`).catch(() => ({ ok: false })),
        fetch(`${API_BASE}/api/pcap/benchmark`).catch(() => ({ ok: false })),
      ]);

      if (
        !healthResponse.ok ||
        !statsResponse.ok ||
        !activeResponse.ok ||
        !historyResponse.ok
      ) {
        throw new Error("API request failed");
      }

      const healthData = await healthResponse.json();
      const statsData = await statsResponse.json();
      const activeData = await activeResponse.json();
      const historyData = await historyResponse.json();

      setHealth(healthData.status === "healthy");
      setStats(statsData);
      setActiveAlerts(activeData.alerts);
      setHistory(historyData.alerts);
      setLastUpdated(new Date());

      if (filesResponse.ok) {
        const filesData = await filesResponse.json();
        setPcapFiles(filesData.files || []);
      }

      if (benchmarkResponse.ok) {
        const bmData = await benchmarkResponse.json();
        if (bmData && bmData.packet_count > 0) {
          setBenchmarkResult(bmData);
        }
      }
    } catch (error) {
      console.error("Failed to fetch CTD data:", error);
      setHealth(false);
    } finally {
      setLoading(false);
    }
  }

  async function handleGeneratePcap() {
    try {
      setIsGenerating(true);
      setPcapMessage("Generating synthetic gateway PCAP with multi-host traffic & attacks...");
      const res = await fetch(`${API_BASE}/api/pcap/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          out: "demo.pcap",
          attacks: ["scan", "syn_flood", "exfil", "beacon", "dga", "tls"],
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setPcapMessage(`Generated ${data.packet_count} packets in ${data.pcap_file} (${data.attacks_included.length} attack vectors)`);
        await fetchData();
      } else {
        setPcapMessage(`Generation failed: ${data.detail || "Error"}`);
      }
    } catch (err) {
      setPcapMessage(`Error: ${err.message}`);
    } finally {
      setIsGenerating(false);
    }
  }

  async function handleReplayPcap() {
    try {
      setIsReplaying(true);
      setPcapMessage(`Streaming ${selectedPcap} through detection pipeline...`);
      const isMaxSpeed = replaySpeed === "max";
      const speedMultiplier = isMaxSpeed ? 1.0 : parseFloat(replaySpeed);

      const res = await fetch(`${API_BASE}/api/pcap/replay`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pcap_file: selectedPcap,
          speed: speedMultiplier,
          max_speed: isMaxSpeed,
        }),
      });

      const data = await res.json();
      if (res.ok) {
        setBenchmarkResult(data.benchmark);
        setPcapMessage(
          `Replay Complete: ${data.benchmark.packet_count} packets processed at ${data.benchmark.sustained_pps.toFixed(1)} pkt/s (${data.benchmark.sustained_mbps.toFixed(2)} Mbps)`
        );
        await fetchData();
      } else {
        setPcapMessage(`Replay failed: ${data.detail || "Error"}`);
      }
    } catch (err) {
      setPcapMessage(`Replay error: ${err.message}`);
    } finally {
      setIsReplaying(false);
    }
  }

  async function handleValidateAccuracy() {
    try {
      setIsValidating(true);
      setPcapMessage("Evaluating detection accuracy against ground truth...");
      const manifestName = `${selectedPcap}.ground_truth.json`;
      const res = await fetch(`${API_BASE}/api/pcap/validate?manifest=${encodeURIComponent(manifestName)}`);
      const data = await res.json();
      if (res.ok) {
        setValidationReport(data.report);
        const rep = data.report;
        setPcapMessage(
          `Validation Complete: ${rep.true_positives}/${rep.expected_attacks} attacks caught (${((rep.recall || 0) * 100).toFixed(0)}% Recall, ${((rep.precision || 0) * 100).toFixed(1)}% Precision)`
        );
      } else {
        setPcapMessage(`Validation failed: ${data.detail || "Manifest not found"}`);
      }
    } catch (err) {
      setPcapMessage(`Validation error: ${err.message}`);
    } finally {
      setIsValidating(false);
    }
  }

  async function triggerSimulation(attackType) {
    try {
      setSimulating(attackType);
      const res = await fetch(`${API_BASE}/api/alerts/simulate/${attackType}`, {
        method: "POST",
      });
      if (res.ok) {
        await fetchData();
      }
    } catch (err) {
      console.error("Simulation failed:", err);
    } finally {
      setSimulating(null);
    }
  }

  async function resolveAllAlerts() {
    try {
      setSimulating("RESOLVE_ALL");
      const res = await fetch(`${API_BASE}/api/alerts/resolve-all`, {
        method: "POST",
      });
      if (res.ok) {
        await fetchData();
      }
    } catch (err) {
      console.error("Resolve failed:", err);
    } finally {
      setSimulating(null);
    }
  }

  async function clearHistory() {
    if (!window.confirm("Clear all Incident History & Audit logs?")) return;
    try {
      setSimulating("CLEAR_HISTORY");
      const res = await fetch(`${API_BASE}/api/alerts/clear-history`, {
        method: "POST",
      });
      if (res.ok) {
        await fetchData();
      }
    } catch (err) {
      console.error("Clear history failed:", err);
    } finally {
      setSimulating(null);
    }
  }

  async function clearAllData() {
    if (
      !window.confirm(
        "Reset ALL system data? (This clears Active Threats, Incident History, and resets all counters to 0)"
      )
    )
      return;
    try {
      setSimulating("CLEAR_ALL");
      const res = await fetch(`${API_BASE}/api/alerts/clear-all`, {
        method: "POST",
      });
      if (res.ok) {
        setBenchmarkResult(null);
        setValidationReport(null);
        setPcapMessage(null);
        await fetchData();
      }
    } catch (err) {
      console.error("Clear all failed:", err);
    } finally {
      setSimulating(null);
    }
  }

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  const filteredActive =
    filterType === "ALL"
      ? activeAlerts
      : activeAlerts.filter((a) => a.attack_type === filterType);

  const filteredHistory =
    filterType === "ALL"
      ? history
      : history.filter((a) => a.attack_type === filterType);

  if (loading && !stats) {
    return (
      <div className="loading-screen">
        <Shield size={48} className="spin-slow" />
        <h1>SentinelFlow-CTD</h1>
        <p>Connecting to detection server at {API_BASE}...</p>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={24} />
          </div>
          <div>
            <h1>SentinelFlow-CTD</h1>
            <span>Cyber Threat Detection & Autonomous Monitoring</span>
          </div>
        </div>

        <div className="topbar-right">
          <div className="ingest-badge">
            <Layers size={14} />
            <span>READ-ONLY PCAP INGEST (DATA DIODE ALIGNED)</span>
          </div>

          <div className="system-status">
            <span className={`status-dot ${health ? "healthy" : "offline"}`} />
            <span>{health ? "7 / 7 DETECTORS ARMED" : "API OFFLINE"}</span>

            <button
              className="refresh-button"
              onClick={fetchData}
              title="Refresh Telemetry"
            >
              <RefreshCw size={18} />
            </button>
          </div>
        </div>
      </header>

      <main className="dashboard">
        {/* Page Heading & Mode Switcher */}
        <section className="page-heading">
          <div>
            <h2>Threat Matrix & Ingest Benchmarking</h2>
            <p>
              Passive streaming threat detection across 7 specialized rule & AI
              detectors with verified ground truth accuracy.
            </p>
          </div>

          {lastUpdated && (
            <div className="heading-actions">
              <span className="updated">
                Updated {lastUpdated.toLocaleTimeString()}
              </span>
              <button
                className="test-panel-toggle"
                onClick={() => setShowTestPanel(!showTestPanel)}
              >
                <SlidersHorizontal size={14} />
                {showTestPanel ? "Hide Ingest Controls" : "Show Ingest Controls"}
              </button>
            </div>
          )}
        </section>

        {/* Global Summary Statistics */}
        <section className="stats-grid">
          <StatCard
            icon={<Activity size={22} />}
            label="Total Incidents"
            value={stats?.total_alerts ?? 0}
          />
          <StatCard
            icon={<AlertTriangle size={22} />}
            label="Active Threats"
            value={stats?.active_alerts ?? 0}
            danger={stats?.active_alerts > 0}
          />
          <StatCard
            icon={<CheckCircle size={22} />}
            label="Resolved Alerts"
            value={stats?.resolved_alerts ?? 0}
          />
          <StatCard
            icon={<Gauge size={22} />}
            label="Demonstrated Throughput"
            value={
              benchmarkResult
                ? `${benchmarkResult.sustained_mbps.toFixed(2)} Mbps`
                : "Awaiting Ingest"
            }
            highlight={benchmarkResult != null}
          />
        </section>

        {/* PCAP Ingest, Replay & Benchmarking Hub */}
        {showTestPanel && (
          <section className="pcap-hub-card">
            <div className="pcap-hub-header">
              <div className="pcap-hub-title">
                <FileCode size={20} className="text-primary" />
                <div>
                  <h4>PCAP Replay & Throughput Benchmark Console</h4>
                  <p>
                    Replay simulated multi-host gateway captures through the streaming 1-second window pipeline.
                  </p>
                </div>
              </div>

              <div className="pcap-hub-actions">
                <button
                  className="pcap-btn btn-generate"
                  onClick={handleGeneratePcap}
                  disabled={isGenerating || isReplaying}
                >
                  <Sparkles size={14} />
                  {isGenerating ? "Generating..." : "1. Generate PCAP"}
                </button>

                <div className="speed-select-wrapper">
                  <span>Speed:</span>
                  <select
                    value={replaySpeed}
                    onChange={(e) => setReplaySpeed(e.target.value)}
                    disabled={isReplaying}
                  >
                    <option value="max">⚡ Max Benchmark Speed</option>
                    <option value="4.0">4x Fast Forward</option>
                    <option value="2.0">2x Fast</option>
                    <option value="1.0">1x Real-Time</option>
                  </select>
                </div>

                <button
                  className="pcap-btn btn-replay"
                  onClick={handleReplayPcap}
                  disabled={isReplaying || isGenerating}
                >
                  <Play size={14} />
                  {isReplaying ? "Streaming..." : "2. Replay PCAP"}
                </button>

                <button
                  className="pcap-btn btn-validate"
                  onClick={handleValidateAccuracy}
                  disabled={isValidating || isReplaying}
                >
                  <Award size={14} />
                  {isValidating ? "Scoring..." : "3. Score Accuracy"}
                </button>
              </div>
            </div>

            {pcapMessage && (
              <div className="pcap-notification-banner">
                <span>{pcapMessage}</span>
              </div>
            )}

            {/* Live Benchmark KPIs Grid */}
            {benchmarkResult && (
              <div className="benchmark-kpis-grid">
                <div className="kpi-box">
                  <span className="kpi-label">Packets Processed</span>
                  <strong className="kpi-value">{benchmarkResult.packet_count.toLocaleString()}</strong>
                </div>
                <div className="kpi-box">
                  <span className="kpi-label">Sustained Packet Rate</span>
                  <strong className="kpi-value">{benchmarkResult.sustained_pps.toFixed(1)} <small>pkt/s</small></strong>
                </div>
                <div className="kpi-box">
                  <span className="kpi-label">Throughput Target</span>
                  <strong className="kpi-value text-accent">{benchmarkResult.sustained_mbps.toFixed(2)} <small>Mbps</small></strong>
                </div>
                <div className="kpi-box">
                  <span className="kpi-label">Observed Flows</span>
                  <strong className="kpi-value">{benchmarkResult.flows_seen} <small>({benchmarkResult.flow_rate.toFixed(1)} flows/s)</small></strong>
                </div>
                <div className="kpi-box">
                  <span className="kpi-label">Replay Duration</span>
                  <strong className="kpi-value">{benchmarkResult.wall_elapsed.toFixed(2)}s</strong>
                </div>
              </div>
            )}

            {/* Ground Truth Validation Report Card */}
            {validationReport && (
              <div className="validation-report-card">
                <div className="validation-report-top">
                  <div className="val-title">
                    <CheckCircle2 size={18} className="text-success" />
                    <strong>Ground-Truth Detection Accuracy Report</strong>
                  </div>
                  <div className="val-scores">
                    <span className="score-badge score-recall">
                      Recall: {((validationReport.recall || 0) * 100).toFixed(0)}%
                    </span>
                    <span className="score-badge score-precision">
                      Precision: {((validationReport.precision || 0) * 100).toFixed(1)}%
                    </span>
                    <span className="score-badge score-f1">
                      F1 Score: {((validationReport.f1 || 0) * 100).toFixed(1)}%
                    </span>
                  </div>
                </div>

                <div className="validation-table-wrapper">
                  <table className="validation-table">
                    <thead>
                      <tr>
                        <th>Attacker IP</th>
                        <th>Target Threat Class</th>
                        <th>Detection Result</th>
                        <th>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {validationReport.detailed_results?.map((item, idx) => (
                        <tr key={idx}>
                          <td className="source">{item.source_ip}</td>
                          <td><strong>{item.attack_type}</strong></td>
                          <td>
                            {item.caught ? (
                              <span className="badge-caught">
                                <CheckCircle2 size={12} /> CAUGHT
                              </span>
                            ) : (
                              <span className="badge-missed">
                                <XCircle size={12} /> MISSED
                              </span>
                            )}
                          </td>
                          <td>{item.caught ? `${Math.round(item.confidence * 100)}%` : "--"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Attack Simulation Presets & Reset Controls */}
            <div className="sim-sub-bar">
              <div className="sim-sub-title">
                <Cpu size={15} />
                <span>Instant Vector Testing Presets:</span>
              </div>
              <div className="sim-quick-grid">
                {DETECTORS_CONFIG.map((det) => (
                  <button
                    key={det.type}
                    className="sim-quick-btn"
                    onClick={() => triggerSimulation(det.type)}
                    disabled={simulating !== null}
                    title={`Simulate ${det.label}`}
                  >
                    <span
                      className="sim-quick-dot"
                      style={{ background: det.color }}
                    />
                    <span>{det.label}</span>
                  </button>
                ))}
              </div>

              <div className="sim-danger-actions">
                <button
                  className="resolve-all-btn"
                  onClick={resolveAllAlerts}
                  disabled={simulating !== null || activeAlerts.length === 0}
                  title="Mark all active alerts as resolved"
                >
                  <RotateCcw size={13} />
                  Resolve Active
                </button>
                <button
                  className="clear-history-btn"
                  onClick={clearHistory}
                  disabled={simulating !== null || history.length === 0}
                  title="Clear all resolved alerts from history"
                >
                  <Trash2 size={13} />
                  Clear History
                </button>
                <button
                  className="reset-all-btn"
                  onClick={clearAllData}
                  disabled={simulating !== null && simulating !== "CLEAR_ALL"}
                  title="Reset all incidents, active threats, and history to 0"
                >
                  <RotateCcw size={13} />
                  Reset System
                </button>
              </div>
            </div>
          </section>
        )}

        {/* 7-Detector Matrix Grid */}
        <section className="detector-matrix-section">
          <div className="section-header">
            <div>
              <h3>Armed Threat Detectors</h3>
              <p>Specialized heuristic engines & unsupervised AI model status</p>
            </div>
          </div>
          <div className="detectors-grid">
            {DETECTORS_CONFIG.map((det) => {
              const IconComponent = det.icon;
              const count = stats?.attack_types?.[det.type] ?? 0;
              const hasActive = activeAlerts.some(
                (a) => a.attack_type === det.type
              );

              return (
                <div
                  key={det.type}
                  className={`detector-card ${hasActive ? "has-active" : ""}`}
                  onClick={() =>
                    setFilterType(filterType === det.type ? "ALL" : det.type)
                  }
                  title="Click to filter by this attack type"
                >
                  <div className="detector-card-top">
                    <div
                      className="detector-icon-wrapper"
                      style={{
                        background: `${det.color}15`,
                        color: det.color,
                      }}
                    >
                      <IconComponent size={20} />
                    </div>
                    <span
                      className={`detector-status-pill ${
                        hasActive ? "pill-danger" : "pill-online"
                      }`}
                    >
                      {hasActive ? "DETECTED" : "ARMED"}
                    </span>
                  </div>

                  <h4>{det.label}</h4>
                  <p>{det.description}</p>

                  <div className="detector-card-bottom">
                    <span>Incidents</span>
                    <strong>{count}</strong>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Attack Filter Tabs */}
        <div className="filter-tabs">
          <button
            className={`filter-tab ${filterType === "ALL" ? "active" : ""}`}
            onClick={() => setFilterType("ALL")}
          >
            All Attacks ({history.length})
          </button>
          {DETECTORS_CONFIG.map((det) => {
            const count =
              stats?.attack_types?.[det.type] ||
              history.filter((a) => a.attack_type === det.type).length;
            if (count === 0 && filterType !== det.type) return null;
            return (
              <button
                key={det.type}
                className={`filter-tab ${
                  filterType === det.type ? "active" : ""
                }`}
                onClick={() => setFilterType(det.type)}
              >
                {det.label} ({count})
              </button>
            );
          })}
        </div>

        {/* Active Threats List */}
        <section className="content-section">
          <div className="section-header">
            <div>
              <h3>Active Threats</h3>
              <p>Live security incidents detected in streaming observation windows</p>
            </div>
            <div className="section-header-actions">
              {filteredActive.length > 0 && (
                <button
                  className="resolve-threats-btn-small"
                  onClick={resolveAllAlerts}
                  disabled={simulating !== null}
                >
                  <RotateCcw size={13} />
                  Resolve All
                </button>
              )}
              <span className="count-badge danger-badge">
                {filteredActive.length}
              </span>
            </div>
          </div>

          {filteredActive.length === 0 ? (
            <div className="empty-state">
              <CheckCircle size={36} />
              <h4>No Active Threats</h4>
              <p>
                {filterType === "ALL"
                  ? "All network flows are within normal behavioral baselines."
                  : `No active ${filterType} incidents currently detected.`}
              </p>
            </div>
          ) : (
            <div className="alert-list">
              {filteredActive.map((alert) => (
                <AlertCard key={alert.alert_id} alert={alert} />
              ))}
            </div>
          )}
        </section>

        {/* Incident History Table */}
        <section className="content-section">
          <div className="section-header">
            <div>
              <h3>Incident History & Audit Log</h3>
              <p>Chronological record of all analyzed security events</p>
            </div>
            <div className="section-header-actions">
              {filteredHistory.length > 0 && (
                <button
                  className="clear-history-btn-secondary"
                  onClick={clearHistory}
                  disabled={simulating !== null}
                  title="Clear all resolved historical incidents"
                >
                  <Trash2 size={13} />
                  Clear History
                </button>
              )}
              <span className="count-badge">{filteredHistory.length}</span>
            </div>
          </div>

          {filteredHistory.length === 0 ? (
            <div className="empty-state">
              <p>No historical incidents found.</p>
            </div>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Source IP</th>
                    <th>Attack Type</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Events</th>
                    <th>Confidence</th>
                    <th>Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredHistory.map((alert) => (
                    <tr key={alert.alert_id}>
                      <td>#{alert.alert_id}</td>
                      <td className="source">{alert.source_ip}</td>
                      <td>
                        <strong>{formatAttackType(alert.attack_type)}</strong>
                      </td>
                      <td>
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td>
                        <StatusBadge status={alert.status} />
                      </td>
                      <td>{alert.event_count}</td>
                      <td>
                        <div className="confidence-cell">
                          <div className="confidence-mini-bar">
                            <div
                              style={{
                                width: `${Math.round(
                                  (alert.confidence || 0) * 100
                                )}%`,
                              }}
                            />
                          </div>
                          <span>
                            {Math.round((alert.confidence || 0) * 100)}%
                          </span>
                        </div>
                      </td>
                      <td>
                        {alert.duration
                          ? `${alert.duration.toFixed(1)}s`
                          : "< 1s"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Attack Type Distribution */}
        <section className="attack-summary">
          <h3>Attack Class Breakdown</h3>
          <div className="attack-list">
            {DETECTORS_CONFIG.map((det) => {
              const count = stats?.attack_types?.[det.type] ?? 0;
              const pct = history.length
                ? Math.round((count / history.length) * 100)
                : 0;

              return (
                <div className="attack-row" key={det.type}>
                  <div className="attack-row-label">
                    <span
                      className="attack-dot"
                      style={{ background: det.color }}
                    />
                    <span>{det.label}</span>
                  </div>
                  <div className="attack-bar">
                    <div
                      style={{
                        width: `${pct}%`,
                        background: det.color,
                      }}
                    />
                  </div>
                  <strong>
                    {count} <small>({pct}%)</small>
                  </strong>
                </div>
              );
            })}
          </div>
        </section>
      </main>

      <footer>
        SentinelFlow-CTD · Real-Time Passive Cyber Threat Detection Engine (SIH-Aligned PCAP Replay)
      </footer>
    </div>
  );
}

function StatCard({ icon, label, value, danger = false, highlight = false }) {
  return (
    <div className={`stat-card ${danger ? "danger" : ""} ${highlight ? "highlight" : ""}`}>
      <div className="stat-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function AlertCard({ alert }) {
  const config =
    DETECTORS_CONFIG.find((d) => d.type === alert.attack_type) || {};
  const Icon = config.icon || AlertTriangle;

  return (
    <div className="alert-card">
      <div
        className="alert-icon"
        style={{
          background: config.color ? `${config.color}15` : "#ffecec",
          color: config.color || "#d94b4b",
        }}
      >
        <Icon size={24} />
      </div>

      <div className="alert-main">
        <div className="alert-title">
          <strong>{config.label || alert.attack_type}</strong>
          <span className="attack-code-tag">{alert.attack_type}</span>
          <SeverityBadge severity={alert.severity} />
          <StatusBadge status={alert.status} />
        </div>

        <div className="alert-meta">
          <span>
            Source IP: <strong>{alert.source_ip}</strong>
          </span>
          <span>
            Confidence:{" "}
            <strong>{Math.round((alert.confidence || 0) * 100)}%</strong>
          </span>
          <span>
            Observed Events: <strong>{alert.event_count}</strong>
          </span>
          {alert.duration > 0 && (
            <span>
              Duration: <strong>{alert.duration.toFixed(1)}s</strong>
            </span>
          )}
        </div>

        {alert.reasons && alert.reasons.length > 0 && (
          <div className="reasons">
            <span>Supporting Evidence & Features:</span>
            <ul>
              {alert.reasons.map((reason, index) => (
                <li key={index}>{reason}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  return (
    <span className={`badge severity-${(severity || "LOW").toLowerCase()}`}>
      {severity}
    </span>
  );
}

function StatusBadge({ status }) {
  return (
    <span className={`badge status-${(status || "ACTIVE").toLowerCase()}`}>
      {status}
    </span>
  );
}

function formatAttackType(type) {
  const item = DETECTORS_CONFIG.find((d) => d.type === type);
  return item ? item.label : type;
}

export default App;
