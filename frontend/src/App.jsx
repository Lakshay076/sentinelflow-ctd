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
  Moon,
  Sun,
} from "lucide-react";
import { AnimatePresence, motion, MotionConfig } from "framer-motion";



import { API_BASE, DETECTORS_CONFIG } from "./config";
import moniLogo from "./assets/moni-logo.png";
import moniLogoDark from "./assets/moni-logo-1.png";
import { StatCard } from "./components/StatCard";
import { AlertCard } from "./components/AlertCard";
import { SeverityBadge, StatusBadge } from "./components/Badges";
import { ScrollBackground } from "./components/ScrollBackground";
import { AboutMoniPage } from "./pages/AboutMoniPage";
import { OverviewPage } from "./pages/OverviewPage";
import { LiveMonitoringPage } from "./pages/LiveMonitoringPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { AnalyticsPage } from "./pages/AnalyticsPage";
import { ThreatIntelligencePage } from "./pages/ThreatIntelligencePage";
import { DemoLabPage } from "./pages/DemoLabPage";
import { TeamPage } from "./pages/TeamPage";





function App() {
  const [currentPage, setCurrentPage] = useState("overview");
  const [theme, setTheme] = useState(
    () => localStorage.getItem("moni-theme") || "light"
  );

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

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("moni-theme", theme);
  }, [theme]);

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
    <MotionConfig reducedMotion="user">
      <ScrollBackground />
      <div className="app-shell">
  <aside className="sidebar">
    <button
      className="sidebar-brand"
      onClick={() => setCurrentPage("overview")}
    >
      <img src={theme === "dark" ? moniLogoDark : moniLogo} alt="MONI Logo" className="brand-logo" />
      <div className="sidebar-brand-copy">
        <div className="sidebar-brand-title">
          <span>MONI</span>
        </div>
        <span className="sidebar-brand-subtitle">Monitoring Network Intelligence</span>
        <span className="sidebar-brand-descriptor">Cyber Threat Detection</span>
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
          className="theme-toggle"
          onClick={() => setTheme(theme === "light" ? "dark" : "light")}
          title="Toggle theme"
          aria-label="Toggle theme"
        >
          {theme === "light" ? <Moon size={17} /> : <Sun size={17} />}
        </button>

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
        <AnimatePresence mode="wait">
          <motion.div
            key={currentPage}
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
            style={{ width: "100%", height: "100%" }}
          >
            {currentPage === "overview" && (
              <OverviewPage
                lastUpdated={lastUpdated}
                stats={stats}
                benchmarkResult={benchmarkResult}
                activeAlerts={activeAlerts}
                history={history}
                filterType={filterType}
                setFilterType={setFilterType}
              />
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
                simulating={simulating}
                triggerSimulation={triggerSimulation}
                isGenerating={isGenerating}
                isReplaying={isReplaying}
                isValidating={isValidating}
                handleGeneratePcap={handleGeneratePcap}
                handleReplayPcap={handleReplayPcap}
                handleValidateAccuracy={handleValidateAccuracy}
                pcapFiles={pcapFiles}
                selectedPcap={selectedPcap}
                setSelectedPcap={setSelectedPcap}
                replaySpeed={replaySpeed}
                setReplaySpeed={setReplaySpeed}
                benchmarkResult={benchmarkResult}
                validationReport={validationReport}
                pcapMessage={pcapMessage}
                activeAlerts={activeAlerts}
                history={history}
                resolveAllAlerts={resolveAllAlerts}
                clearHistory={clearHistory}
                clearAllData={clearAllData}
              />
            )}
            {currentPage === "team" && <TeamPage />}
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
          </motion.div>
        </AnimatePresence>
      </main>

      <footer>
         MONI · Passive Cyber Threat Detection Platform · SIH26145
      </footer>
    </div>
    </div>
    </MotionConfig>
  );
}

export default App;
