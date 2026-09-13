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
  Trash2,
  FileCode,
  Gauge,
  CheckCircle2,
  XCircle,
  Cpu,
  Layers,
  Sparkles,
  Award,
  X,
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
  const [currentPage, setCurrentPage] = useState("overview");

  const [stats, setStats] = useState(null);
  const [activeAlerts, setActiveAlerts] = useState([]);
  const [history, setHistory] = useState([]);
  const [liveMetrics, setLiveMetrics] = useState({
    latest: null,
    history: [],
  });

  const [health, setHealth] = useState(false);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [simulating, setSimulating] = useState(null);
  const [filterType, setFilterType] = useState("ALL");

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
        metricsResponse,
        filesResponse,
        benchmarkResponse,
      ] = await Promise.all([
        fetch(`${API_BASE}/api/health`),
        fetch(`${API_BASE}/api/stats`),
        fetch(`${API_BASE}/api/alerts/active`),
        fetch(`${API_BASE}/api/alerts/history`),
        fetch(`${API_BASE}/api/metrics/live`),
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
      const metricsData = await metricsResponse.json();


      setHealth(healthData.status === "healthy");
      setStats(statsData);
      setLiveMetrics(metricsData);
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

    const pageTitles = {
    overview: {
      title: "Overview",
      subtitle: "Network security operations at a glance",
    },
    live: {
      title: "Live Monitoring",
      subtitle: "Real-time passive traffic observation",
    },
    incidents: {
      title: "Incidents",
      subtitle: "Threat events and investigation history",
    },
    intel: {
      title: "Threat Intelligence",
      subtitle: "Detection coverage and threat classification",
    },
    analytics: {
      title: "Analytics",
      subtitle: "Performance, traffic and detection analytics",
    },
    demo: {
      title: "Demo Lab",
      subtitle: "Controlled threat simulation and PCAP replay",
    },
    team: {
      title: "Our Team",
      subtitle: "The team behind MONI",
    },
    about: {
      title: "About MONI",
      subtitle: "Architecture, mission and deployment model",
    },
  };

  const activePage = pageTitles[currentPage] || pageTitles.overview;

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
      <div className="app-shell">
  <aside className="sidebar">
    <button
      className="sidebar-brand"
      onClick={() => setCurrentPage("overview")}
    >
      <div className="brand-icon">
        <Shield size={22} />
      </div>

      <div className="sidebar-brand-copy">
        <div className="sidebar-brand-title">
          <span>MONI</span>
          <small>CTD</small>
        </div>
        <span>Cyber Threat Detection</span>
      </div>
    </button>

    <div className="sidebar-section-label">OPERATIONS</div>

    <nav className="sidebar-nav" aria-label="Primary navigation">
      {[
        { id: "overview", label: "Overview", icon: Activity },
        { id: "live", label: "Live Monitoring", icon: Radio },
        { id: "incidents", label: "Incidents", icon: AlertTriangle },
        { id: "intel", label: "Threat Intelligence", icon: Shield },
        { id: "analytics", label: "Analytics", icon: Gauge },
      ].map((item) => {
        const Icon = item.icon;

        return (
          <button
            key={item.id}
            className={`sidebar-nav-item ${
              currentPage === item.id ? "active" : ""
            }`}
            onClick={() => setCurrentPage(item.id)}
          >
            <Icon size={17} />
            <span>{item.label}</span>

            {item.id === "incidents" && stats?.active_alerts > 0 && (
              <span className="nav-count">
                {stats.active_alerts}
              </span>
            )}
          </button>
        );
      })}
    </nav>

    <div className="sidebar-section-label sidebar-demo-label">
      RESOURCES
    </div>

    <nav className="sidebar-nav">
      {[
        { id: "demo", label: "Demo Lab", icon: Zap },
        { id: "team", label: "Our Team", icon: Award },
        { id: "about", label: "About MONI", icon: BrainCircuit },
      ].map((item) => {
        const Icon = item.icon;

        return (
          <button
            key={item.id}
            className={`sidebar-nav-item ${
              currentPage === item.id ? "active" : ""
            }`}
            onClick={() => setCurrentPage(item.id)}
          >
            <Icon size={17} />
            <span>{item.label}</span>
          </button>
        );
      })}
    </nav>

    <div className="sidebar-footer">
      <div className="sidebar-system">
        <span
          className={`status-dot ${health ? "healthy" : "offline"}`}
        />
        <div>
          <strong>{health ? "System Operational" : "API Offline"}</strong>
          <span>Passive monitoring</span>
        </div>
      </div>

      <div className="sidebar-readonly">
        <Layers size={13} />
        <span>READ-ONLY SENSOR</span>
      </div>
    </div>
  </aside>

  <div className="app-main">
    <header className="topbar">
      <div className="topbar-page">
        <div>
          <h1>{activePage.title}</h1>
          <span>{activePage.subtitle}</span>
        </div>

        {lastUpdated && (
          <span className="topbar-updated">
            Updated {lastUpdated.toLocaleTimeString()}
          </span>
        )}
      </div>

      <div className="topbar-actions">
        <div className="topbar-passive">
          <Radio size={14} />
          <span>PASSIVE / READ-ONLY</span>
        </div>

        <div className="system-status">
          <span
            className={`status-dot ${health ? "healthy" : "offline"}`}
          />
          <span>
            {health ? "SYSTEM OPERATIONAL" : "API OFFLINE"}
          </span>
        </div>

        <button
          className="refresh-button"
          onClick={fetchData}
          title="Refresh telemetry"
          aria-label="Refresh telemetry"
        >
          <RefreshCw size={17} />
        </button>
      </div>
    </header>


      <main className="dashboard">
        {currentPage === "overview" && (
          <>
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
      </>
      )}
      {currentPage === "live" && (
        <LiveMonitoringPage
          liveMetrics={liveMetrics}
          activeAlerts={activeAlerts}
        />
      )}

      {currentPage === "incidents" && (
        <IncidentsPage
          activeAlerts={activeAlerts}
          history={history}
          stats={stats}
          filterType={filterType}
          setFilterType={setFilterType}
          onResolveAll={resolveAllAlerts}
          onClearHistory={clearHistory}
          simulating={simulating}
        />
      )}

      {currentPage === "intel" && (
        <ThreatIntelligencePage
          activeAlerts={activeAlerts}
          history={history}
        />
      )}

      {currentPage === "analytics" && (
        <AnalyticsPage
          liveMetrics={liveMetrics}
          stats={stats}
          history={history}
          activeAlerts={activeAlerts}
        />
      )}

      {currentPage === "demo" && (
        <DemoLabPage
          pcapFiles={pcapFiles}
          selectedPcap={selectedPcap}
          setSelectedPcap={setSelectedPcap}
          replaySpeed={replaySpeed}
          setReplaySpeed={setReplaySpeed}
          benchmarkResult={benchmarkResult}
          validationReport={validationReport}
          pcapMessage={pcapMessage}
          isGenerating={isGenerating}
          isReplaying={isReplaying}
          isValidating={isValidating}
          simulating={simulating}
          activeAlerts={activeAlerts}
          history={history}
          handleGeneratePcap={handleGeneratePcap}
          handleReplayPcap={handleReplayPcap}
          handleValidateAccuracy={handleValidateAccuracy}
          triggerSimulation={triggerSimulation}
          resolveAllAlerts={resolveAllAlerts}
          clearHistory={clearHistory}
          clearAllData={clearAllData}
        />
      )}

      {currentPage === "about" && <AboutMoniPage />}

      {currentPage !== "overview" &&
        currentPage !== "live" &&
        currentPage !== "incidents" &&
        currentPage !== "intel" &&
        currentPage !== "analytics" &&
        currentPage !== "demo" &&
        currentPage !== "team" &&
        currentPage !== "about" && (
        <section className="page-placeholder">
          <div className="page-placeholder-body">
            <Shield size={34} />
            <h2>{activePage.title}</h2>
            <p>
              This MONI module is being prepared. The existing detection
              pipeline remains active in the background.
            </p>
          </div>
        </section>
      )}
      </main>

      <footer>
         MONI · Passive Cyber Threat Detection Platform · SIH26145
      </footer>
    </div>
   </div>
  );
}

function AboutMoniPage() {
  const architecture = [
    {
      step: "01",
      title: "Passive Traffic Ingest",
      text: "MONI receives a one-directional copy of network traffic from a TAP, SPAN port, data diode or exported flow source.",
    },
    {
      step: "02",
      title: "Streaming Feature Engine",
      text: "Observed packets and flows are converted into bounded-window behavioral features without requiring payload inspection.",
    },
    {
      step: "03",
      title: "Detection & Correlation",
      text: "Specialized threat detectors and anomaly analysis evaluate traffic behaviour and correlate related evidence.",
    },
    {
      step: "04",
      title: "Alert & Investigation",
      text: "Detections are stored as structured incidents with confidence, supporting evidence, source and responder context.",
    },
  ];

  const principles = [
    {
      icon: Radio,
      title: "Passive by Design",
      text: "The monitoring path observes copied traffic and has no return path into the protected production network.",
    },
    {
      icon: Lock,
      title: "No Payload Decryption",
      text: "Encrypted sessions can be analysed through observable metadata and behavioural characteristics without decrypting application content.",
    },
    {
      icon: BrainCircuit,
      title: "Behavioural Detection",
      text: "MONI combines specialized heuristic detectors with anomaly analysis to identify suspicious network behaviour.",
    },
    {
      icon: Activity,
      title: "Near Real-Time",
      text: "Streaming windows allow traffic behaviour to be evaluated incrementally with bounded processing latency.",
    },
  ];

  const threats = [
    "Volumetric / protocol DDoS",
    "Botnet C2 beaconing",
    "DGA and DNS tunnelling",
    "TLS metadata anomalies",
    "Reconnaissance and port scanning",
    "Suspicious data exfiltration",
  ];

  return (
    <>
      <section className="about-hero">
        <div className="about-hero-copy">
          <span className="section-kicker">CYBER THREAT DETECTION</span>
          <h2>MONI turns passive traffic into actionable security intelligence.</h2>
          <p>
            MONI is a passive cyber threat detection platform designed for
            environments where network traffic can be observed but the
            monitoring system must not interfere with production operations.
          </p>
        </div>

        <div className="about-hero-status">
          <Shield size={24} />
          <div>
            <strong>PASSIVE SENSOR</strong>
            <span>Read-only observation architecture</span>
          </div>
        </div>
      </section>

      <section className="page-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">MISSION</span>
            <h3>Built for One-Directional Network Visibility</h3>
          </div>
        </div>

        <div className="about-mission">
          <p>
            Critical infrastructure may provide monitoring systems with a
            copied stream of network traffic through passive mirroring or
            hardware-enforced one-way links. MONI is designed around that
            constraint: intelligence must come from what can be observed,
            rather than from probes, inline controls or active response.
          </p>
        </div>
      </section>

      <section className="page-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">ARCHITECTURE</span>
            <h3>From Traffic Copy to Security Alert</h3>
          </div>
          <span className="section-muted">Streaming detection pipeline</span>
        </div>

        <div className="about-flow">
          {architecture.map((item, index) => (
            <div className="about-flow-item" key={item.step}>
              <div className="about-flow-number">{item.step}</div>
              <div className="about-flow-copy">
                <strong>{item.title}</strong>
                <p>{item.text}</p>
              </div>
              {index < architecture.length - 1 && (
                <div className="about-flow-line" />
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="page-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">DESIGN PRINCIPLES</span>
            <h3>Security Without Network Interference</h3>
          </div>
        </div>

        <div className="about-principles">
          {principles.map((item) => {
            const Icon = item.icon;

            return (
              <article className="about-principle" key={item.title}>
                <div className="about-principle-icon">
                  <Icon size={18} />
                </div>
                <div>
                  <h4>{item.title}</h4>
                  <p>{item.text}</p>
                </div>
              </article>
            );
          })}
        </div>
      </section>

      <section className="page-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">THREAT COVERAGE</span>
            <h3>What MONI Can Detect</h3>
          </div>
          <span className="section-muted">Current prototype coverage</span>
        </div>

        <div className="about-threats">
          {threats.map((threat, index) => (
            <div className="about-threat" key={threat}>
              <span>{String(index + 1).padStart(2, "0")}</span>
              <strong>{threat}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="page-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">DEPLOYMENT MODEL</span>
            <h3>Designed to Sit Outside the Production Path</h3>
          </div>
        </div>

        <div className="about-deployment">
          <div className="about-deployment-path">
            <div className="deployment-node">
              <Globe size={17} />
              <strong>Production Network</strong>
              <span>Gateway / Critical Infrastructure</span>
            </div>

            <div className="deployment-connector">
              <span>PASSIVE COPY</span>
              <div />
            </div>

            <div className="deployment-node active">
              <Shield size={17} />
              <strong>MONI Sensor</strong>
              <span>Read-only detection enclave</span>
            </div>
          </div>

          <div className="about-deployment-note">
            <Lock size={16} />
            <p>
              No inline blocking, probing or outbound mitigation is required
              by the monitoring architecture.
            </p>
          </div>
        </div>
      </section>

      <section className="about-footer-note">
        <div>
          <span className="section-kicker">SIH26145</span>
          <h3>AI-Based Detection of Cyber Threats in Unidirectional IP Traffic</h3>
          <p>
            MONI demonstrates how passive network telemetry can be transformed
            into near-real-time threat intelligence while respecting the
            one-directional monitoring constraint.
          </p>
        </div>

        <div className="about-footer-badge">
          <Shield size={20} />
          <span>MONI</span>
        </div>
      </section>
    </>
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

function IncidentsPage({
  activeAlerts,
  history,
  stats,
  filterType,
  setFilterType,
  onResolveAll,
  onClearHistory,
  simulating,
}) {
  const filteredActive =
    filterType === "ALL"
      ? activeAlerts
      : activeAlerts.filter((alert) => alert.attack_type === filterType);

  const filteredHistory =
    filterType === "ALL"
      ? history
      : history.filter((alert) => alert.attack_type === filterType);

  const [selectedIncident, setSelectedIncident] = useState(null);

  const highSeverityCount = history.filter(
    (alert) => (alert.severity || "").toUpperCase() === "HIGH"
  ).length;

  const mediumSeverityCount = history.filter(
    (alert) => (alert.severity || "").toUpperCase() === "MEDIUM"
  ).length;

  return (
    <section className="incidents-page">
      <div className="incidents-intro">
        <div>
          <h2>Security Incidents</h2>
          <p>
            Investigate threats detected by the MONI streaming detection
            pipeline and review their supporting evidence.
          </p>
        </div>

        <div className="incident-posture">
          <span
            className={`status-dot ${
              activeAlerts.length > 0 ? "danger" : "healthy"
            }`}
          />
          <div>
            <strong>
              {activeAlerts.length > 0
                ? `${activeAlerts.length} ACTIVE THREAT${
                    activeAlerts.length === 1 ? "" : "S"
                  }`
                : "NO ACTIVE THREATS"}
            </strong>
            <span>Detection pipeline status</span>
          </div>
        </div>
      </div>

      <div className="incident-kpi-grid">
        <div className="incident-kpi-card">
          <span>Total Incidents</span>
          <strong>{stats?.total_alerts ?? history.length}</strong>
          <small>All recorded detections</small>
        </div>

        <div className="incident-kpi-card incident-kpi-danger">
          <span>Active Threats</span>
          <strong>{stats?.active_alerts ?? activeAlerts.length}</strong>
          <small>Require attention</small>
        </div>

        <div className="incident-kpi-card">
          <span>Resolved</span>
          <strong>{stats?.resolved_alerts ?? 0}</strong>
          <small>Closed incidents</small>
        </div>

        <div className="incident-kpi-card">
          <span>High Severity</span>
          <strong>{highSeverityCount}</strong>
          <small>{mediumSeverityCount} medium severity</small>
        </div>
      </div>

      <div className="incident-filter-card">
        <div>
          <strong>Incident Filters</strong>
          <span>Focus investigation on a specific threat class.</span>
        </div>

        <div className="incident-filter-buttons">
          <button
            className={`incident-filter-btn ${
              filterType === "ALL" ? "active" : ""
            }`}
            onClick={() => setFilterType("ALL")}
          >
            All
            <span>{history.length}</span>
          </button>

          {DETECTORS_CONFIG.map((detector) => {
            const count = history.filter(
              (alert) => alert.attack_type === detector.type
            ).length;

            if (count === 0 && filterType !== detector.type) {
              return null;
            }

            return (
              <button
                key={detector.type}
                className={`incident-filter-btn ${
                  filterType === detector.type ? "active" : ""
                }`}
                onClick={() => setFilterType(detector.type)}
              >
                {detector.label}
                <span>{count}</span>
              </button>
            );
          })}
        </div>
      </div>

      <section className="incident-section-card">
        <div className="incident-section-header">
          <div>
            <h3>Active Threats</h3>
            <p>
              Live incidents currently maintained by the alert lifecycle
              manager.
            </p>
          </div>

          <div className="incident-section-actions">
            {filteredActive.length > 0 && (
              <button
                className="resolve-threats-btn-small"
                onClick={onResolveAll}
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
          <div className="incident-empty-state">
            <CheckCircle size={34} />
            <h4>No Active Threats</h4>
            <p>
              {filterType === "ALL"
                ? "All observed network behavior is currently within the active alert baseline."
                : `No active ${formatAttackType(
                    filterType
                  )} incidents are currently detected.`}
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

      <section className="incident-section-card">
        <div className="incident-section-header">
          <div>
            <h3>Incident History & Audit Log</h3>
            <p>
              Chronological record of detections generated by the monitoring
              pipeline.
            </p>
          </div>

          <div className="incident-section-actions">
            {filteredHistory.length > 0 && (
              <button
                className="clear-history-btn-secondary"
                onClick={onClearHistory}
                disabled={simulating !== null}
              >
                <Trash2 size={13} />
                Clear History
              </button>
            )}

            <span className="count-badge">{filteredHistory.length}</span>
          </div>
        </div>

        {filteredHistory.length === 0 ? (
          <div className="incident-empty-state compact">
            <p>No historical incidents found.</p>
          </div>
        ) : (
          <div className="table-wrapper incident-table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Source IP</th>
                  <th>Threat</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Events</th>
                  <th>Confidence</th>
                  <th>Duration</th>
                </tr>
              </thead>

              <tbody>
                {filteredHistory.map((alert) => (
                  <tr
                    key={alert.alert_id}
                    className={
                      selectedIncident?.alert_id === alert.alert_id
                        ? "incident-row selected"
                        : "incident-row"
                    }
                    onClick={() => setSelectedIncident(alert)}
                    title="Click to investigate this incident"
                  >
                    <td className="incident-id">#{alert.alert_id}</td>

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

      {selectedIncident && (
        <IncidentDrawer
          alert={selectedIncident}
          onClose={() => setSelectedIncident(null)}
        />
      )}
    </section>
  );
}

function IncidentDrawer({ alert, onClose }) {
  const confidence = Math.round((alert.confidence || 0) * 100);

  const formatTimestamp = (timestamp) =>
    timestamp
      ? new Date(timestamp * 1000).toLocaleString()
      : "—";

  return (
    <div className="incident-drawer-backdrop" onClick={onClose}>
      <aside
        className="incident-drawer"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="incident-drawer-header">
          <div>
            <span>INCIDENT #{alert.alert_id}</span>
            <h3>{formatAttackType(alert.attack_type)}</h3>
          </div>

          <button
            className="incident-drawer-close"
            onClick={onClose}
            aria-label="Close incident details"
            title="Close"
          >
            <X size={18} />
          </button>
        </div>

        <div className="incident-drawer-badges">
          <SeverityBadge severity={alert.severity} />
          <StatusBadge status={alert.status} />
          <span className="incident-confidence-badge">
            {confidence}% confidence
          </span>
        </div>

        <div className="incident-drawer-section">
          <div className="incident-drawer-section-title">
            <span>Incident Overview</span>
          </div>

          <div className="incident-detail-grid">
            <div>
              <span>Source IP</span>
              <strong className="incident-mono">{alert.source_ip}</strong>
            </div>

            <div>
              <span>Threat Class</span>
              <strong>{formatAttackType(alert.attack_type)}</strong>
            </div>

            <div>
              <span>Observed Events</span>
              <strong>{alert.event_count}</strong>
            </div>

            <div>
              <span>Duration</span>
              <strong>
                {alert.duration > 0
                  ? `${alert.duration.toFixed(1)}s`
                  : "< 1s"}
              </strong>
            </div>
          </div>
        </div>

        <div className="incident-drawer-section">
          <div className="incident-drawer-section-title">
            <span>Detection Confidence</span>
            <strong>{confidence}%</strong>
          </div>

          <div className="incident-confidence-track">
            <div
              className="incident-confidence-fill"
              style={{ width: `${confidence}%` }}
            />
          </div>

          <p className="incident-drawer-muted">
            Confidence reported by the active MONI detection engine.
          </p>
        </div>

        <div className="incident-drawer-section">
          <div className="incident-drawer-section-title">
            <span>Supporting Evidence</span>
          </div>

          {alert.reasons && alert.reasons.length > 0 ? (
            <ul className="incident-evidence-list">
              {alert.reasons.map((reason, index) => (
                <li key={index}>
                  <CheckCircle2 size={14} />
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="incident-drawer-muted">
              No supporting evidence was recorded for this incident.
            </p>
          )}
        </div>

        <div className="incident-drawer-section">
          <div className="incident-drawer-section-title">
            <span>Incident Timeline</span>
          </div>

          <div className="incident-timeline">
            <div className="incident-timeline-item">
              <span className="incident-timeline-dot" />
              <div>
                <strong>First Observed</strong>
                <span>{formatTimestamp(alert.first_seen)}</span>
              </div>
            </div>

            <div className="incident-timeline-item">
              <span className="incident-timeline-dot" />
              <div>
                <strong>Last Seen</strong>
                <span>{formatTimestamp(alert.last_seen)}</span>
              </div>
            </div>

            {alert.resolved_at && (
              <div className="incident-timeline-item resolved">
                <span className="incident-timeline-dot" />
                <div>
                  <strong>Resolved</strong>
                  <span>{formatTimestamp(alert.resolved_at)}</span>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="incident-drawer-footer">
          <span>Detection-only monitoring</span>
          <span>No network response or blocking performed</span>
        </div>
      </aside>
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

function LiveMonitoringPage({ liveMetrics, activeAlerts }) {
  const latest = liveMetrics?.latest;
  const points = liveMetrics?.history || [];

  const maxPps = Math.max(
    ...points.map((point) => point.packets_per_second || 0),
    1
  );

  return (
    <section className="live-monitoring-page">
      <div className="live-page-intro">
        <div>
          <h2>Network Telemetry</h2>
          <p>
            Real-time observation of traffic received by the MONI sensor.
            No payload decryption or inline intervention is performed.
          </p>
        </div>

        <div className="live-page-status">
          <span
            className={`status-dot ${latest ? "healthy" : "offline"}`}
          />
          <div>
            <strong>
              {latest ? "LIVE TELEMETRY" : "WAITING FOR TELEMETRY"}
            </strong>
            <span>1-second observation windows</span>
          </div>
        </div>
      </div>

      <div className="live-kpi-grid">
        <div className="live-kpi-card">
          <span>Packets / sec</span>
          <strong>
            {latest?.packets_per_second?.toFixed(1) ?? "—"}
          </strong>
          <small>Current window</small>
        </div>

        <div className="live-kpi-card">
          <span>Flows / sec</span>
          <strong>
            {latest?.flows_per_second?.toFixed(1) ?? "—"}
          </strong>
          <small>Flow creation rate</small>
        </div>

        <div className="live-kpi-card">
          <span>Bandwidth</span>
          <strong>
            {latest?.mbps?.toFixed(3) ?? "—"}
            <small> Mbps</small>
          </strong>
          <small>Observed traffic</small>
        </div>

        <div className="live-kpi-card">
          <span>Active Flows</span>
          <strong>{latest?.active_flows ?? "—"}</strong>
          <small>Current window</small>
        </div>

        <div className="live-kpi-card">
          <span>Source IPs</span>
          <strong>{latest?.unique_sources ?? "—"}</strong>
          <small>Unique sources</small>
        </div>

        <div className="live-kpi-card">
          <span>Destination IPs</span>
          <strong>{latest?.unique_destinations ?? "—"}</strong>
          <small>Unique destinations</small>
        </div>
      </div>

      <div className="live-chart-card">
        <div className="live-chart-header">
          <div>
            <h3>Packet Rate</h3>
            <p>Last 60 seconds of completed observation windows</p>
          </div>

          <div className="live-chart-current">
            <strong>
              {latest?.packets_per_second?.toFixed(1) ?? "—"}
            </strong>
            <span>pkt/s</span>
          </div>
        </div>

        <div className="traffic-chart">
          {points.length === 0 ? (
            <div className="traffic-chart-empty">
              Waiting for traffic telemetry...
            </div>
          ) : (
            points.map((point, index) => {
              const value = point.packets_per_second || 0;
              const height = Math.max(3, (value / maxPps) * 100);

              return (
                <div
                  className="traffic-chart-column"
                  key={`${point.timestamp}-${index}`}
                  title={`${value.toFixed(1)} pkt/s`}
                >
                  <div
                    className="traffic-chart-bar"
                    style={{ height: `${height}%` }}
                  />
                </div>
              );
            })
          )}
        </div>

        <div className="traffic-chart-axis">
          <span>60s ago</span>
          <span>30s ago</span>
          <span>Now</span>
        </div>
      </div>

      <div className="live-detail-grid">
        <section className="live-detail-card">
          <div className="live-detail-header">
            <div>
              <h3>Protocol Activity</h3>
              <p>Current observation window</p>
            </div>
          </div>

          <div className="protocol-grid">
            <div>
              <span>TCP</span>
              <strong>{latest?.tcp_packets ?? "—"}</strong>
            </div>

            <div>
              <span>UDP</span>
              <strong>{latest?.udp_packets ?? "—"}</strong>
            </div>

            <div>
              <span>ICMP</span>
              <strong>{latest?.icmp_packets ?? "—"}</strong>
            </div>

            <div>
              <span>TCP SYN</span>
              <strong>{latest?.tcp_syn ?? "—"}</strong>
            </div>

            <div>
              <span>TCP ACK</span>
              <strong>{latest?.tcp_ack ?? "—"}</strong>
            </div>

            <div>
              <span>TCP RST</span>
              <strong>{latest?.tcp_rst ?? "—"}</strong>
            </div>
          </div>
        </section>

        <section className="live-detail-card">
          <div className="live-detail-header">
            <div>
              <h3>Active Threats</h3>
              <p>Detections from the streaming pipeline</p>
            </div>

            <span className="count-badge danger-badge">
              {activeAlerts?.length ?? 0}
            </span>
          </div>

          {activeAlerts?.length ? (
            <div className="live-threat-list">
              {activeAlerts.slice(0, 5).map((alert) => (
                <div
                  className="live-threat-row"
                  key={alert.alert_id}
                >
                  <div>
                    <strong>
                      {formatAttackType(alert.attack_type)}
                    </strong>
                    <span>{alert.source_ip}</span>
                  </div>

                  <div className="live-threat-meta">
                    <SeverityBadge severity={alert.severity} />
                    <span>
                      {Math.round((alert.confidence || 0) * 100)}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="live-no-threats">
              <CheckCircle size={22} />
              <span>No active threats detected</span>
            </div>
          )}
        </section>
      </div>
    </section>
  );
}

export default App;

function AnalyticsPage({
  liveMetrics,
  stats,
  history,
  activeAlerts,
}) {
  const latest = liveMetrics?.latest;
  const points = liveMetrics?.history || [];

  const recentPoints = points.slice(-30);

  const values = recentPoints.map(
    (point) => Number(point.packets_per_second) || 0
  );

  const peakPps = values.length ? Math.max(...values) : 0;
  const averagePps = values.length
    ? values.reduce((sum, value) => sum + value, 0) / values.length
    : 0;

  const mbpsValues = recentPoints.map(
    (point) => Number(point.mbps) || 0
  );

  const averageMbps = mbpsValues.length
    ? mbpsValues.reduce((sum, value) => sum + value, 0) /
      mbpsValues.length
    : 0;

  const attackTypes = stats?.attack_types || {};

  const detectionRows = DETECTORS_CONFIG.map((detector) => ({
    ...detector,
    count: attackTypes[detector.type] || 0,
  }));

  const maxDetectionCount = Math.max(
    ...detectionRows.map((row) => row.count),
    1
  );

  const protocolTotal =
    (latest?.tcp_packets || 0) +
    (latest?.udp_packets || 0) +
    (latest?.icmp_packets || 0);

  const protocolRows = [
    {
      label: "TCP",
      value: latest?.tcp_packets || 0,
      percentage: protocolTotal
        ? ((latest.tcp_packets || 0) / protocolTotal) * 100
        : 0,
    },
    {
      label: "UDP",
      value: latest?.udp_packets || 0,
      percentage: protocolTotal
        ? ((latest.udp_packets || 0) / protocolTotal) * 100
        : 0,
    },
    {
      label: "ICMP",
      value: latest?.icmp_packets || 0,
      percentage: protocolTotal
        ? ((latest.icmp_packets || 0) / protocolTotal) * 100
        : 0,
    },
  ];

  return (
    <>
      <section className="analytics-intro">
        <div>
          <span className="section-kicker">NETWORK PERFORMANCE</span>
          <h2>Traffic & Detection Analytics</h2>
          <p>
            Aggregated telemetry from MONI's passive observation windows,
            combined with recorded threat detections.
          </p>
        </div>

        <div className="analytics-window-status">
          <span className={`status-dot ${latest ? "healthy" : "offline"}`} />
          <div>
            <strong>{latest ? "TELEMETRY ACTIVE" : "WAITING"}</strong>
            <span>{points.length} observation windows available</span>
          </div>
        </div>
      </section>

      <section className="analytics-kpi-grid">
        <div className="analytics-kpi">
          <span>Current Packet Rate</span>
          <strong>{latest?.packets_per_second?.toFixed(1) ?? "—"}</strong>
          <small>packets / sec</small>
        </div>

        <div className="analytics-kpi">
          <span>Peak Packet Rate</span>
          <strong>{peakPps.toFixed(1)}</strong>
          <small>last {recentPoints.length || 0} windows</small>
        </div>

        <div className="analytics-kpi">
          <span>Average Packet Rate</span>
          <strong>{averagePps.toFixed(1)}</strong>
          <small>packets / sec</small>
        </div>

        <div className="analytics-kpi">
          <span>Current Bandwidth</span>
          <strong>{latest?.mbps?.toFixed(3) ?? "—"}</strong>
          <small>Mbps</small>
        </div>

        <div className="analytics-kpi">
          <span>Flow Creation Rate</span>
          <strong>{latest?.flows_per_second?.toFixed(1) ?? "—"}</strong>
          <small>flows / sec</small>
        </div>

        <div className="analytics-kpi">
          <span>Active Flows</span>
          <strong>{latest?.active_flows ?? "—"}</strong>
          <small>current window</small>
        </div>
      </section>

      <section className="analytics-section">
        <div className="analytics-section-header">
          <div>
            <span className="section-kicker">TRAFFIC TELEMETRY</span>
            <h3>Packet Rate Trend</h3>
          </div>
          <span>Last {recentPoints.length || 0} completed windows</span>
        </div>

        <div className="analytics-chart">
          {recentPoints.length === 0 ? (
            <div className="analytics-empty">
              Waiting for traffic telemetry...
            </div>
          ) : (
            recentPoints.map((point, index) => {
              const value = Number(point.packets_per_second) || 0;
              const height = Math.max(
                4,
                peakPps ? (value / peakPps) * 100 : 4
              );

              return (
                <div
                  className="analytics-bar-column"
                  key={`${point.timestamp}-${index}`}
                  title={`${value.toFixed(1)} pkt/s`}
                >
                  <div
                    className="analytics-bar"
                    style={{ height: `${height}%` }}
                  />
                </div>
              );
            })
          )}
        </div>

        <div className="analytics-axis">
          <span>Older</span>
          <span>Recent</span>
          <span>Now</span>
        </div>
      </section>

      <section className="analytics-two-column">
        <section className="analytics-panel">
          <div className="analytics-section-header">
            <div>
              <span className="section-kicker">PROTOCOL MIX</span>
              <h3>Current Protocol Activity</h3>
            </div>
            <span>{protocolTotal.toLocaleString()} packets</span>
          </div>

          <div className="protocol-analytics">
            {protocolRows.map((protocol) => (
              <div className="protocol-analytics-row" key={protocol.label}>
                <div className="protocol-analytics-label">
                  <strong>{protocol.label}</strong>
                  <span>{protocol.value.toLocaleString()} packets</span>
                </div>

                <div className="protocol-analytics-track">
                  <div
                    className="protocol-analytics-fill"
                    style={{ width: `${protocol.percentage}%` }}
                  />
                </div>

                <strong>
                  {protocol.percentage.toFixed(1)}%
                </strong>
              </div>
            ))}
          </div>
        </section>

        <section className="analytics-panel">
          <div className="analytics-section-header">
            <div>
              <span className="section-kicker">TRAFFIC SCOPE</span>
              <h3>Current Network Scope</h3>
            </div>
          </div>

          <div className="scope-grid">
            <div>
              <span>Source IPs</span>
              <strong>{latest?.unique_sources ?? "—"}</strong>
            </div>

            <div>
              <span>Destination IPs</span>
              <strong>{latest?.unique_destinations ?? "—"}</strong>
            </div>

            <div>
              <span>TCP SYN</span>
              <strong>{latest?.tcp_syn ?? "—"}</strong>
            </div>

            <div>
              <span>TCP ACK</span>
              <strong>{latest?.tcp_ack ?? "—"}</strong>
            </div>

            <div>
              <span>TCP RST</span>
              <strong>{latest?.tcp_rst ?? "—"}</strong>
            </div>

            <div>
              <span>Avg Bandwidth</span>
              <strong>{averageMbps.toFixed(3)} Mbps</strong>
            </div>
          </div>
        </section>
      </section>

      <section className="analytics-section">
        <div className="analytics-section-header">
          <div>
            <span className="section-kicker">DETECTION ANALYTICS</span>
            <h3>Threat Detection Distribution</h3>
          </div>

          <span>
            {stats?.total_alerts ?? history.length} recorded incidents
          </span>
        </div>

        <div className="detection-analytics">
          {detectionRows.map((detector) => {
            const percentage = detector.count
              ? (detector.count / maxDetectionCount) * 100
              : 0;

            return (
              <div
                className="detection-analytics-row"
                key={detector.type}
              >
                <div className="detection-analytics-name">
                  <strong>{detector.label}</strong>
                  <span>{detector.type}</span>
                </div>

                <div className="detection-analytics-track">
                  <div
                    className="detection-analytics-fill"
                    style={{ width: `${percentage}%` }}
                  />
                </div>

                <strong>{detector.count}</strong>
              </div>
            );
          })}
        </div>
      </section>

      <section className="analytics-footer-summary">
        <div>
          <span>ACTIVE THREATS</span>
          <strong>{activeAlerts.length}</strong>
        </div>
        <div>
          <span>RESOLVED INCIDENTS</span>
          <strong>{stats?.resolved_alerts ?? 0}</strong>
        </div>
        <div>
          <span>TOTAL INCIDENTS</span>
          <strong>{stats?.total_alerts ?? history.length}</strong>
        </div>
      </section>
    </>
  );
}

function ThreatIntelligencePage({ activeAlerts, history }) {
  const allIncidents = [...activeAlerts, ...history];

  const threatDefinitions = [
    {
      type: "SYN_FLOOD",
      label: "SYN Flood",
      description: "High-rate TCP SYN activity indicating possible volumetric flooding.",
      evidence: "SYN ratio, SYN/sec, flow creation rate",
      severity: "HIGH",
    },
    {
      type: "PORT_SCAN",
      label: "Port Scanning",
      description: "Multi-port reconnaissance against one or more destinations.",
      evidence: "Unique ports, flows/sec, SYN ratio",
      severity: "HIGH",
    },
    {
      type: "C2_BEACONING",
      label: "C2 Beaconing",
      description: "Repeated connections with highly regular timing patterns.",
      evidence: "Connection intervals, timing variation, repeated destinations",
      severity: "HIGH",
    },
    {
      type: "DGA_DNS_TUNNELLING",
      label: "DGA / DNS Tunnelling",
      description: "Suspicious DNS behaviour involving random-looking or unusually long domains.",
      evidence: "Domain entropy, unique domains, query rate, length",
      severity: "MEDIUM",
    },
    {
      type: "TLS_METADATA_ANOMALY",
      label: "TLS Metadata Anomaly",
      description: "Unusual encrypted-session characteristics without decrypting payloads.",
      evidence: "Cipher count, extension count, SNI presence",
      severity: "MEDIUM",
    },
    {
      type: "DATA_EXFILTRATION",
      label: "Data Exfiltration",
      description: "Sustained asymmetric outbound transfer behaviour.",
      evidence: "Outbound volume, traffic ratio, packet count, transfer rate",
      severity: "HIGH",
    },
  ];

  const activeSources = [...new Set(
    activeAlerts.map((alert) => alert.source_ip).filter(Boolean)
  )];

  const detectionCount = (type) =>
    allIncidents.filter((incident) => incident.attack_type === type).length;

  return (
    <>
      <section className="intel-intro">
        <div>
          <span className="section-kicker">PASSIVE NETWORK INTELLIGENCE</span>
          <p>
            Behavioral intelligence derived from observed network metadata.
            MONI operates in a read-only monitoring path without payload
            decryption or an outbound response path.
          </p>
        </div>

        <div className="intel-status">
          <Shield size={20} />
          <div>
            <strong>READ-ONLY</strong>
            <span>Passive observation active</span>
          </div>
        </div>
      </section>

      <section className="stats-grid">
        <StatCard
          icon={<Shield size={20} />}
          label="Threat Classes"
          value={threatDefinitions.length}
        />
        <StatCard
          icon={<AlertTriangle size={20} />}
          label="Active Threats"
          value={activeAlerts.length}
          danger={activeAlerts.length > 0}
        />
        <StatCard
          icon={<Activity size={20} />}
          label="Observed Sources"
          value={activeSources.length}
        />
        <StatCard
          icon={<Gauge size={20} />}
          label="Recorded Incidents"
          value={allIncidents.length}
        />
      </section>

      <section className="page-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">DETECTION COVERAGE</span>
            <h3>MONI Threat Classes</h3>
          </div>
          <span className="section-muted">
            {threatDefinitions.length} behavioral detectors
          </span>
        </div>

        <div className="intel-grid">
          {threatDefinitions.map((threat) => (
            <article className="intel-card" key={threat.type}>
              <div className="intel-card-top">
                <div>
                  <span className={`severity-badge ${threat.severity.toLowerCase()}`}>
                    {threat.severity}
                  </span>
                  <h4>{threat.label}</h4>
                </div>
                <strong>{detectionCount(threat.type)}</strong>
              </div>

              <p>{threat.description}</p>

              <div className="intel-evidence">
                <span>SUPPORTING TELEMETRY</span>
                <strong>{threat.evidence}</strong>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="page-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">SOURCE INTELLIGENCE</span>
            <h3>Currently Observed Threat Sources</h3>
          </div>
        </div>

        {activeAlerts.length === 0 ? (
          <div className="empty-state">
            <Shield size={28} />
            <h4>No active threat sources</h4>
            <p>
              MONI has no currently active incidents. Passive monitoring
              continues in the background.
            </p>
          </div>
        ) : (
          <div className="intel-source-list">
            {activeAlerts.map((alert) => (
              <div className="intel-source-row" key={alert.alert_id}>
                <div>
                  <strong>{alert.source_ip}</strong>
                  <span>{alert.attack_type.replaceAll("_", " ")}</span>
                </div>

                <div className="intel-source-evidence">
                  <span>CONFIDENCE</span>
                  <strong>{Math.round((alert.confidence || 0) * 100)}%</strong>
                </div>

                <div className="intel-source-evidence">
                  <span>SEVERITY</span>
                  <strong>{alert.severity}</strong>
                </div>

                <div className="intel-source-evidence">
                  <span>EVENTS</span>
                  <strong>{alert.event_count || 1}</strong>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="page-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">INVESTIGATION EVIDENCE</span>
            <h3>Latest Detection Evidence</h3>
          </div>
        </div>

        <div className="intel-evidence-table">
          {activeAlerts.slice(0, 6).map((alert) => (
            <div className="evidence-row" key={`evidence-${alert.alert_id}`}>
              <div>
                <strong>{alert.attack_type.replaceAll("_", " ")}</strong>
                <span>{alert.source_ip}</span>
              </div>

              <div className="evidence-reasons">
                {(alert.reasons || []).slice(0, 3).map((reason, index) => (
                  <span key={index}>• {reason}</span>
                ))}
              </div>

              <strong>
                {Math.round((alert.confidence || 0) * 100)}%
              </strong>
            </div>
          ))}

          {activeAlerts.length === 0 && (
            <div className="empty-state compact">
              <p>Detection evidence will appear here when MONI identifies a threat.</p>
            </div>
          )}
        </div>
      </section>
    </>
  );
}


function DemoLabPage({
  pcapFiles,
  selectedPcap,
  setSelectedPcap,
  replaySpeed,
  setReplaySpeed,
  benchmarkResult,
  validationReport,
  pcapMessage,
  isGenerating,
  isReplaying,
  isValidating,
  simulating,
  activeAlerts,
  history,
  handleGeneratePcap,
  handleReplayPcap,
  handleValidateAccuracy,
  triggerSimulation,
  resolveAllAlerts,
  clearHistory,
  clearAllData,
}) {
  return (
    <>
      {/* Controlled Threat Simulation */}
      <section className="page-section demo-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">CONTROLLED THREAT SIMULATION</span>
            <h3>Detection Scenario Lab</h3>
          </div>
          <span className="section-muted">6 threat vectors</span>
        </div>

        <div className="demo-intro">
          <div>
            <strong>Validate MONI against controlled traffic scenarios</strong>
            <p>
              Trigger a detector through the same alert pipeline used for
              observed traffic. Results appear in Incidents with confidence
              and supporting evidence.
            </p>
          </div>

          <div className="demo-readonly-status">
            <Shield size={17} />
            <span>READ-ONLY DETECTION PATH</span>
          </div>
        </div>

        <div className="demo-vector-grid">
          {DETECTORS_CONFIG
            .filter((det) => det.type !== "ML_ANOMALY")
            .map((det) => {
              const IconComponent = det.icon;
              const isRunning = simulating === det.type;

              return (
                <button
                  key={det.type}
                  className={`demo-vector-btn ${
                    isRunning ? "is-running" : ""
                  }`}
                  onClick={() => triggerSimulation(det.type)}
                  disabled={simulating !== null}
                >
                  <span
                    className="demo-vector-icon"
                    style={{
                      background: `${det.color}15`,
                      color: det.color,
                    }}
                  >
                    <IconComponent size={18} />
                  </span>

                  <span className="demo-vector-copy">
                    <strong>{det.label}</strong>
                    <small>{det.category}</small>
                  </span>

                  <span className="demo-vector-action">
                    {isRunning ? "Running..." : "Run"}
                  </span>
                </button>
              );
            })}
        </div>
      </section>

      {/* PCAP Replay */}
      <section className="page-section demo-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">PCAP REPLAY</span>
            <h3>Streaming Capture Validation</h3>
          </div>
          <span className="section-muted">Same 1-second pipeline</span>
        </div>

        <div className="demo-control-row">
          <button
            className="demo-primary-btn"
            onClick={handleGeneratePcap}
            disabled={isGenerating || isReplaying}
          >
            <Sparkles size={15} />
            {isGenerating ? "Generating..." : "Generate PCAP"}
          </button>

          <div className="demo-select-group">
            <label>Capture</label>
            <select
              value={selectedPcap}
              onChange={(e) => setSelectedPcap(e.target.value)}
              disabled={isReplaying || isGenerating}
            >
              {pcapFiles.length > 0 ? (
                pcapFiles.map((file) => {
                  const filename =
                    typeof file === "string" ? file : file.filename;

                  return (
                    <option key={filename} value={filename}>
                      {filename}
                    </option>
                  );
                })
              ) : (
                <option value="demo.pcap">demo.pcap</option>
              )}
            </select>
          </div>

          <div className="demo-select-group">
            <label>Replay Speed</label>
            <select
              value={replaySpeed}
              onChange={(e) => setReplaySpeed(e.target.value)}
              disabled={isReplaying}
            >
              <option value="max">Max Benchmark Speed</option>
              <option value="4.0">4x Fast Forward</option>
              <option value="2.0">2x Fast</option>
              <option value="1.0">1x Real-Time</option>
            </select>
          </div>

          <button
            className="demo-secondary-btn"
            onClick={handleReplayPcap}
            disabled={isReplaying || isGenerating}
          >
            <Play size={15} />
            {isReplaying ? "Streaming..." : "Replay PCAP"}
          </button>

          <button
            className="demo-secondary-btn"
            onClick={handleValidateAccuracy}
            disabled={isValidating || isReplaying}
          >
            <Award size={15} />
            {isValidating ? "Scoring..." : "Score Accuracy"}
          </button>
        </div>

        {pcapMessage && (
          <div className="demo-message">
            <Activity size={15} />
            <span>{pcapMessage}</span>
          </div>
        )}
      </section>

      {/* Benchmark */}
      {benchmarkResult && (
        <section className="page-section demo-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">THROUGHPUT BENCHMARK</span>
              <h3>Replay Performance</h3>
            </div>
            <span className="section-muted">Measured pipeline output</span>
          </div>

          <div className="demo-kpi-grid">
            <div className="demo-kpi">
              <span>PACKETS PROCESSED</span>
              <strong>
                {benchmarkResult.packet_count.toLocaleString()}
              </strong>
            </div>

            <div className="demo-kpi">
              <span>SUSTAINED PACKET RATE</span>
              <strong>
                {benchmarkResult.sustained_pps.toFixed(1)}
                <small> pkt/s</small>
              </strong>
            </div>

            <div className="demo-kpi highlight">
              <span>THROUGHPUT</span>
              <strong>
                {benchmarkResult.sustained_mbps.toFixed(2)}
                <small> Mbps</small>
              </strong>
            </div>

            <div className="demo-kpi">
              <span>OBSERVED FLOWS</span>
              <strong>
                {benchmarkResult.flows_seen.toLocaleString()}
                <small> ({benchmarkResult.flow_rate.toFixed(1)}/s)</small>
              </strong>
            </div>

            <div className="demo-kpi">
              <span>REPLAY DURATION</span>
              <strong>{benchmarkResult.wall_elapsed.toFixed(2)}s</strong>
            </div>
          </div>
        </section>
      )}

      {/* Accuracy */}
      {validationReport && (
        <section className="page-section demo-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">GROUND-TRUTH VALIDATION</span>
              <h3>Detection Accuracy</h3>
            </div>
            <span className="section-muted">PCAP manifest comparison</span>
          </div>

          <div className="demo-score-grid">
            <div>
              <span>RECALL</span>
              <strong>
                {((validationReport.recall || 0) * 100).toFixed(0)}%
              </strong>
            </div>

            <div>
              <span>PRECISION</span>
              <strong>
                {((validationReport.precision || 0) * 100).toFixed(1)}%
              </strong>
            </div>

            <div>
              <span>F1 SCORE</span>
              <strong>
                {((validationReport.f1 || 0) * 100).toFixed(1)}%
              </strong>
            </div>
          </div>

          <div className="demo-validation-table">
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Threat Class</th>
                  <th>Result</th>
                  <th>Confidence</th>
                </tr>
              </thead>

              <tbody>
                {validationReport.detailed_results?.map((item, idx) => (
                  <tr key={idx}>
                    <td>{item.source_ip}</td>
                    <td>{item.attack_type}</td>
                    <td>
                      {item.caught ? (
                        <span className="demo-caught">
                          <CheckCircle2 size={12} />
                          CAUGHT
                        </span>
                      ) : (
                        <span className="demo-missed">
                          <XCircle size={12} />
                          MISSED
                        </span>
                      )}
                    </td>
                    <td>
                      {item.caught
                        ? `${Math.round(item.confidence * 100)}%`
                        : "--"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Lab Controls */}
      <section className="page-section demo-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">LAB CONTROLS</span>
            <h3>Incident State Management</h3>
          </div>
          <span className="section-muted">
            {activeAlerts.length} active · {history.length} recorded
          </span>
        </div>

        <div className="demo-management-row">
          <button
            className="demo-secondary-btn"
            onClick={resolveAllAlerts}
            disabled={simulating !== null || activeAlerts.length === 0}
          >
            <RotateCcw size={14} />
            Resolve Active
          </button>

          <button
            className="demo-secondary-btn"
            onClick={clearHistory}
            disabled={simulating !== null || history.length === 0}
          >
            <Trash2 size={14} />
            Clear History
          </button>

          <button
            className="demo-reset-btn"
            onClick={clearAllData}
            disabled={simulating !== null}
          >
            <RotateCcw size={14} />
            Reset System
          </button>
        </div>
      </section>
    </>
  );
}
