import React from "react";

export function SeverityBadge({ severity }) {
  return (
    <span className={`badge severity-${(severity || "LOW").toLowerCase()}`}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }) {
  return (
    <span className={`badge status-${(status || "ACTIVE").toLowerCase()}`}>
      {status}
    </span>
  );
}
