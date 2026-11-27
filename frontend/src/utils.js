import { DETECTORS_CONFIG } from "./config";

export function formatAttackType(type) {
  const item = DETECTORS_CONFIG.find((d) => d.type === type);
  return item ? item.label : type;
}

export function formatSourceIp(sourceIp, { includeRaw = false } = {}) {
  if (sourceIp === "__NETWORK__") {
    return includeRaw ? "Network-Wide (__NETWORK__)" : "Network-Wide";
  }
  return sourceIp || "Unknown";
}

export function dedupeIncidents(activeAlerts = [], history = []) {
  const byId = new Map();
  for (const inc of [...history, ...activeAlerts]) {
    if (inc?.alert_id != null) {
      byId.set(inc.alert_id, inc);
    } else {
      byId.set(`anon-${byId.size}`, inc);
    }
  }
  return Array.from(byId.values());
}

export function computeXAxisDomain(sortedPoints = [], nowMs = Date.now()) {
  const timestamps = sortedPoints
    .map((p) => (p?.timestamp ? Number(p.timestamp) * 1000 : NaN))
    .filter((t) => Number.isFinite(t) && t > 0);

  if (timestamps.length === 0) {
    return { min: nowMs - 60000, max: nowMs, isHistorical: false };
  }

  const minTs = timestamps[0];
  const maxTs = timestamps[timestamps.length - 1];
  const isHistorical = nowMs - maxTs > 65000;

  if (!isHistorical) {
    const endMs = Math.max(nowMs, maxTs);
    return {
      min: endMs - 60000,
      max: endMs,
      isHistorical: false,
    };
  }

  const span = maxTs - minTs;
  return {
    min: span >= 5000 ? minTs : maxTs - 60000,
    max: span >= 5000 ? maxTs : maxTs + 1000,
    isHistorical: true,
  };
}
