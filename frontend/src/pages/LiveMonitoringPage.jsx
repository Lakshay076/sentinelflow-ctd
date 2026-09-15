import React from "react";
import { CheckCircle } from "lucide-react";
import { SeverityBadge } from "../components/Badges";
import { formatAttackType } from "../utils";
import { LiveTrafficChart } from "../components/LiveTrafficChart";
import { Reveal } from "../components/Reveal";

export function LiveMonitoringPage({ liveMetrics, activeAlerts }) {
  const latest = liveMetrics?.latest;
  const points = liveMetrics?.history || [];

  const nowMs = Date.now();
  const latestTimestampMs = latest?.timestamp ? latest.timestamp * 1000 : 0;
  const isStale = latest && (nowMs - latestTimestampMs > 65000); // 65 second grace period
  const displayLatest = isStale ? null : latest;
  
  const latestTsString = latest?.timestamp 
    ? new Date(latest.timestamp * 1000).toLocaleTimeString() 
    : '';

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
            className={`status-dot ${!isStale && displayLatest ? "healthy" : "offline"}`}
          />
          <div>
            <strong>
              {!isStale && displayLatest ? "LIVE TELEMETRY" : (isStale ? "TELEMETRY STALE" : "WAITING FOR TELEMETRY")}
            </strong>
            <span>1-second observation windows</span>
          </div>
        </div>
      </div>

      <Reveal delay={0.1}>
        <div className="live-kpi-grid">
        <div className="live-kpi-card">
          <span>Packets / sec</span>
          <strong>
            {displayLatest?.packets_per_second?.toFixed(1) ?? "—"}
          </strong>
          <small>Current window</small>
        </div>

        <div className="live-kpi-card">
          <span>Flows / sec</span>
          <strong>
            {displayLatest?.flows_per_second?.toFixed(1) ?? "—"}
          </strong>
          <small>Flow creation rate</small>
        </div>

        <div className="live-kpi-card">
          <span>Bandwidth</span>
          <strong>
            {displayLatest?.mbps?.toFixed(3) ?? "—"}
            <small> Mbps</small>
          </strong>
          <small>Observed traffic</small>
        </div>

        <div className="live-kpi-card">
          <span>Active Flows</span>
          <strong>{displayLatest?.active_flows ?? "—"}</strong>
          <small>Current window</small>
        </div>

        <div className="live-kpi-card">
          <span>Source IPs</span>
          <strong>{displayLatest?.unique_sources ?? "—"}</strong>
          <small>Unique sources</small>
        </div>

        <div className="live-kpi-card">
          <span>Destination IPs</span>
          <strong>{displayLatest?.unique_destinations ?? "—"}</strong>
          <small>Unique destinations</small>
        </div>
      </div>
      </Reveal>

      <Reveal delay={0.2}>
        <div className="live-chart-card">
        <div className="live-chart-header">
          <div>
            <h3>Packet Rate</h3>
            <p>Last 60 seconds of completed observation windows</p>
          </div>

          <div className="live-chart-current" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
            <div>
              <strong>
                {displayLatest?.packets_per_second?.toFixed(1) ?? "—"}
              </strong>
              <span>pkt/s</span>
            </div>
            {isStale && latestTsString && (
              <div style={{ fontSize: '11px', color: 'var(--text-danger)', marginTop: '4px', textAlign: 'right' }}>
                Telemetry stale<br/>
                <span style={{ color: 'var(--text-muted)' }}>Last: {latestTsString}</span>
              </div>
            )}
          </div>
        </div>

        <div className="traffic-chart" style={{ height: '180px', position: 'relative' }}>
          {points.length === 0 ? (
            <div className="traffic-chart-empty">
              Waiting for traffic telemetry...
            </div>
          ) : (
            <LiveTrafficChart points={points} maxPps={maxPps} />
          )}
        </div>

        <div className="traffic-chart-axis">
          <span>60s ago</span>
          <span>30s ago</span>
          <span>Now</span>
        </div>
      </div>
      </Reveal>

      <Reveal delay={0.3}>
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
      </Reveal>
    </section>
  );
}
