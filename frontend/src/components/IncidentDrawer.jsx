import React from "react";
import { X, CheckCircle2 } from "lucide-react";
import { SeverityBadge, StatusBadge } from "./Badges";
import { formatAttackType } from "../utils";

export function IncidentDrawer({ alert, onClose }) {
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

        {(alert.predicted_threat || alert.classification_status) && (
          <div className="incident-drawer-section">
            <div className="incident-drawer-section-title">
              <span>Supervised Threat Classification</span>
              <strong>
                {alert.predicted_threat || alert.classification_status}
              </strong>
            </div>

            <div className="incident-detail-grid" style={{ marginBottom: "10px" }}>
              <div>
                <span>Predicted Category</span>
                <strong>{alert.predicted_threat || "—"}</strong>
              </div>
              <div>
                <span>Triage Confidence</span>
                <strong>
                  {alert.threat_confidence != null
                    ? `${Math.round(alert.threat_confidence * 100)}%`
                    : "—"}
                </strong>
              </div>
              <div>
                <span>Status</span>
                <strong>{alert.classification_status || "—"}</strong>
              </div>
              <div>
                <span>Model / Schema</span>
                <strong className="incident-mono">
                  {alert.model_version || "—"}
                  {alert.feature_schema_version
                    ? ` / ${alert.feature_schema_version}`
                    : ""}
                </strong>
              </div>
            </div>

            {alert.threat_confidence != null && (
              <div className="incident-confidence-track" style={{ marginBottom: "10px" }}>
                <div
                  className="incident-confidence-fill"
                  style={{
                    width: `${Math.round(alert.threat_confidence * 100)}%`,
                    background:
                      alert.predicted_threat === "UNCLASSIFIED"
                        ? "var(--text-muted)"
                        : "#10b981",
                  }}
                />
              </div>
            )}

            {alert.alternative_predictions && alert.alternative_predictions.length > 0 && (
              <div style={{ marginTop: "8px" }}>
                <span className="incident-drawer-muted" style={{ display: "block", marginBottom: "4px" }}>
                  Top Predictions:
                </span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                  {alert.alternative_predictions.map((alt, idx) => (
                    <span key={idx} className="attack-code-tag">
                      {alt.category || alt.label}:{" "}
                      {Math.round((alt.probability ?? alt.confidence ?? 0) * 100)}%
                    </span>
                  ))}
                </div>
              </div>
            )}

            {alert.supporting_features && Object.keys(alert.supporting_features).length > 0 && (
              <div style={{ marginTop: "10px" }}>
                <span className="incident-drawer-muted" style={{ display: "block", marginBottom: "4px" }}>
                  Top Supporting Flow Features:
                </span>
                <ul className="incident-evidence-list">
                  {Object.entries(alert.supporting_features).map(([feat, val]) => (
                    <li key={feat}>
                      <CheckCircle2 size={14} />
                      <span>
                        <strong>{feat}</strong>:{" "}
                        {typeof val === "number" ? val.toFixed(4) : String(val)}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

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
