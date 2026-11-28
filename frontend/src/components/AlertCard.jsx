import React from "react";
import { AlertTriangle, BrainCircuit } from "lucide-react";
import { DETECTORS_CONFIG } from "../config";
import { SeverityBadge, StatusBadge } from "./Badges";

export function AlertCard({ alert }) {
  const config =
    DETECTORS_CONFIG.find((d) => d.type === alert.attack_type) || {};
  const Icon = config.icon || AlertTriangle;

  return (
    <div className="alert-card">
      <div
        className="alert-icon"
        style={{
          background: config.color ? `${config.color}15` : "var(--severity-critical-bg)",
          color: config.color || "var(--severity-critical)",
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
          {(alert.predicted_threat || alert.classification_status) && (
            <span
              className="attack-code-tag"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "4px",
                background:
                  alert.predicted_threat && alert.predicted_threat !== "UNCLASSIFIED"
                    ? "rgba(16, 185, 129, 0.14)"
                    : "rgba(148, 163, 184, 0.14)",
                color:
                  alert.predicted_threat && alert.predicted_threat !== "UNCLASSIFIED"
                    ? "#34d399"
                    : "var(--text-secondary)",
                border: "1px solid currentColor",
              }}
              title={`Supervised ML Triage (${alert.classification_status || "CLASSIFIED"})`}
            >
              <BrainCircuit size={12} />
              {alert.predicted_threat
                ? `${alert.predicted_threat}${
                    alert.threat_confidence != null
                      ? ` (${Math.round(alert.threat_confidence * 100)}%)`
                      : ""
                  }`
                : alert.classification_status}
            </span>
          )}
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
