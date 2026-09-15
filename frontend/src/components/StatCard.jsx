import React from "react";

export function StatCard({ icon, label, value, danger = false, highlight = false }) {
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
