import React, { useState } from "react";
import { RotateCcw, CheckCircle, Trash2 } from "lucide-react";
import { AlertCard } from "../components/AlertCard";
import { DETECTORS_CONFIG } from "../config";
import { IncidentDrawer } from "../components/IncidentDrawer";
import { SeverityBadge, StatusBadge } from "../components/Badges";
import { IncidentTimeline3D } from "../components/IncidentTimeline3D";
import { formatAttackType } from "../utils";
import { Reveal } from "../components/Reveal";

export function IncidentsPage({
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

      <Reveal delay={0.1}>
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
      </Reveal>

      <Reveal delay={0.2}>
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
      </Reveal>

      <Reveal delay={0.3}>
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
      </Reveal>

      <Reveal delay={0.4}>
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
          {/* <IncidentTimeline3D history={filteredHistory} onIncidentClick={setSelectedIncident} /> */}
          <div className="incident-empty-state compact" style={{ border: '1px dashed var(--border-subtle)', margin: '16px 0', padding: '32px' }}>
            <p style={{ color: 'var(--text-muted)' }}>Interactive 3D Threat Timeline &mdash; Coming Soon</p>
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
      </Reveal>

      {selectedIncident && (
        <IncidentDrawer
          alert={selectedIncident}
          onClose={() => setSelectedIncident(null)}
        />
      )}
    </section>
  );
}
