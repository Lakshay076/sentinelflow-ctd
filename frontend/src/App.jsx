import { useEffect, useState } from "react";
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Server,
} from "lucide-react";

import "./App.css";

const API_BASE = "http://192.168.56.105:8000";

function App() {
  const [stats, setStats] = useState(null);
  const [activeAlerts, setActiveAlerts] = useState([]);
  const [history, setHistory] = useState([]);
  const [health, setHealth] = useState(false);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  async function fetchData() {
    try {
      setLoading(true);

      const [
        healthResponse,
        statsResponse,
        activeResponse,
        historyResponse,
      ] = await Promise.all([
        fetch(`${API_BASE}/api/health`),
        fetch(`${API_BASE}/api/stats`),
        fetch(`${API_BASE}/api/alerts/active`),
        fetch(`${API_BASE}/api/alerts/history`),
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
    } catch (error) {
      console.error("Failed to fetch CTD data:", error);
      setHealth(false);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchData();

    const interval = setInterval(fetchData, 5000);

    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <div className="loading-screen">
        <Shield size={42} />
        <h1>CTD</h1>
        <p>Connecting to detection server...</p>
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
            <h1>CTD</h1>
            <span>Cyber Threat Detection</span>
          </div>
        </div>

        <div className="system-status">
          <span
            className={`status-dot ${
              health ? "healthy" : "offline"
            }`}
          />

          <span>
            {health ? "SYSTEM HEALTHY" : "API OFFLINE"}
          </span>

          <button
            className="refresh-button"
            onClick={fetchData}
            title="Refresh"
          >
            <RefreshCw size={18} />
          </button>
        </div>
      </header>

      <main className="dashboard">
        <section className="page-heading">
          <div>
            <h2>Security Overview</h2>
            <p>
              Detection-only network monitoring and incident
              history.
            </p>
          </div>

          {lastUpdated && (
            <span className="updated">
              Updated{" "}
              {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </section>

        <section className="stats-grid">
          <StatCard
            icon={<Activity size={22} />}
            label="Total Incidents"
            value={stats?.total_alerts ?? 0}
          />

          <StatCard
            icon={<AlertTriangle size={22} />}
            label="Active Alerts"
            value={stats?.active_alerts ?? 0}
            danger
          />

          <StatCard
            icon={<CheckCircle size={22} />}
            label="Resolved"
            value={stats?.resolved_alerts ?? 0}
          />

          <StatCard
            icon={<Server size={22} />}
            label="Port Scans"
            value={
              stats?.attack_types?.PORT_SCAN ?? 0
            }
          />
        </section>

        <section className="content-section">
          <div className="section-header">
            <div>
              <h3>Active Threats</h3>
              <p>Currently active security incidents</p>
            </div>

            <span className="count-badge">
              {activeAlerts.length}
            </span>
          </div>

          {activeAlerts.length === 0 ? (
            <div className="empty-state">
              <CheckCircle size={30} />
              <h4>No active threats</h4>
              <p>
                CTD has not detected an active incident.
              </p>
            </div>
          ) : (
            <div className="alert-list">
              {activeAlerts.map((alert) => (
                <AlertCard
                  key={alert.alert_id}
                  alert={alert}
                />
              ))}
            </div>
          )}
        </section>

        <section className="content-section">
          <div className="section-header">
            <div>
              <h3>Incident History</h3>
              <p>
                Historical security incidents recorded by
                CTD
              </p>
            </div>

            <span className="count-badge">
              {history.length}
            </span>
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Source</th>
                  <th>Attack</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Events</th>
                  <th>Confidence</th>
                </tr>
              </thead>

              <tbody>
                {history.map((alert) => (
                  <tr key={alert.alert_id}>
                    <td>#{alert.alert_id}</td>

                    <td className="source">
                      {alert.source_ip}
                    </td>

                    <td>{alert.attack_type}</td>

                    <td>
                      <SeverityBadge
                        severity={alert.severity}
                      />
                    </td>

                    <td>
                      <StatusBadge
                        status={alert.status}
                      />
                    </td>

                    <td>{alert.event_count}</td>

                    <td>
                      {(alert.confidence * 100).toFixed(
                        0
                      )}
                      %
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="attack-summary">
          <h3>Attack Distribution</h3>

          <div className="attack-list">
            {Object.entries(
              stats?.attack_types ?? {}
            ).map(([type, count]) => (
              <div
                className="attack-row"
                key={type}
              >
                <span>{type}</span>

                <div className="attack-bar">
                  <div
                    style={{
                      width: `${
                        history.length
                          ? (count / history.length) *
                            100
                          : 0
                      }%`,
                    }}
                  />
                </div>

                <strong>{count}</strong>
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer>
        CTD · Detection-only monitoring system
      </footer>
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  danger = false,
}) {
  return (
    <div className={`stat-card ${danger ? "danger" : ""}`}>
      <div className="stat-icon">{icon}</div>

      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function AlertCard({ alert }) {
  return (
    <div className="alert-card">
      <div className="alert-icon">
        <AlertTriangle size={24} />
      </div>

      <div className="alert-main">
        <div className="alert-title">
          <strong>{alert.attack_type}</strong>

          <SeverityBadge
            severity={alert.severity}
          />

          <StatusBadge status={alert.status} />
        </div>

        <div className="alert-meta">
          <span>
            Source: <strong>{alert.source_ip}</strong>
          </span>

          <span>
            Confidence:{" "}
            <strong>
              {(alert.confidence * 100).toFixed(0)}%
            </strong>
          </span>

          <span>
            Events: <strong>{alert.event_count}</strong>
          </span>
        </div>

        <div className="reasons">
          <span>Detection reasons:</span>

          <ul>
            {alert.reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  return (
    <span
      className={`badge severity-${severity.toLowerCase()}`}
    >
      {severity}
    </span>
  );
}

function StatusBadge({ status }) {
  return (
    <span
      className={`badge status-${status.toLowerCase()}`}
    >
      {status}
    </span>
  );
}

export default App;
