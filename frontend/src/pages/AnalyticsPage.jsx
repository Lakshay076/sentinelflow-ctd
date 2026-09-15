import React from "react";
import { DETECTORS_CONFIG } from "../config";
import { AnalyticsTrendChart } from "../components/AnalyticsTrendChart";
import { Reveal } from "../components/Reveal";

export function AnalyticsPage({
  liveMetrics,
  stats,
  history,
  activeAlerts,
}) {
  const latest = liveMetrics?.latest;
  const points = liveMetrics?.history || [];

  const analysisPoints = points;

  const values = analysisPoints.map(
    (point) => Number(point.packets_per_second) || 0
  );

  const peakPps = values.length ? Math.max(...values) : 0;
  const averagePps = values.length
    ? values.reduce((sum, value) => sum + value, 0) / values.length
    : 0;

  const mbpsValues = analysisPoints.map(
    (point) => Number(point.mbps) || 0
  );

  const averageMbps = mbpsValues.length
    ? mbpsValues.reduce((sum, value) => sum + value, 0) /
      mbpsValues.length
    : 0;

  let timeRangeStr = "Waiting for data";
  let windowCountStr = "0 completed observation windows";
  let startStr = "Start";
  let endStr = "End";

  if (analysisPoints.length > 0) {
    const firstPoint = analysisPoints[0];
    const lastPoint = analysisPoints[analysisPoints.length - 1];

    const formatTime = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' }) : '';
    startStr = formatTime(firstPoint.timestamp) || 'Unknown Start';
    endStr = formatTime(lastPoint.timestamp) || 'Unknown End';

    timeRangeStr = `${startStr} – ${endStr}`;
    windowCountStr = `${analysisPoints.length} completed observation windows`;
  }

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

      <Reveal delay={0.1}>
        <section className="analytics-kpi-grid">
        <div className="analytics-kpi">
          <span>Current Packet Rate</span>
          <strong>{latest?.packets_per_second?.toFixed(1) ?? "—"}</strong>
          <small>packets / sec</small>
        </div>

        <div className="analytics-kpi">
          <span>Peak Packet Rate</span>
          <strong>{peakPps.toFixed(1)}</strong>
          <small>historical maximum</small>
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
      </Reveal>

      <Reveal delay={0.2}>
        <section className="analytics-section">
        <div className="analytics-section-header">
          <div>
            <span className="section-kicker">HISTORICAL ANALYSIS</span>
            <h3>Historical Packet Rate</h3>
          </div>
          <span>{windowCountStr}</span>
        </div>

        <AnalyticsTrendChart points={analysisPoints} />

        <div className="analytics-axis">
          <span>{startStr}</span>
          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{timeRangeStr}</span>
          <span>{endStr}</span>
        </div>
        </section>
      </Reveal>

      <Reveal delay={0.3}>
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
      </Reveal>

      <Reveal delay={0.4}>
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
      </Reveal>

      <Reveal delay={0.5}>
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
      </Reveal>
    </>
  );
}
