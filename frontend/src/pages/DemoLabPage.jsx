import React, { useState } from "react";
import { Shield, Sparkles, Play, Award, Activity, CheckCircle2, XCircle, RotateCcw, Trash2 } from "lucide-react";
import { DETECTORS_CONFIG } from "../config";
import { DemoPipelineVisualization } from "../components/DemoPipelineVisualization";
import { Reveal } from "../components/Reveal";

export function DemoLabPage({
  simulating,
  triggerSimulation,
  demoConfig,
  demoCommand,
  isGenerating,
  isReplaying,
  isValidating,
  handleGeneratePcap,
  handleReplayPcap,
  handleValidateAccuracy,
  pcapFiles,
  selectedPcap,
  setSelectedPcap,
  replaySpeed,
  setReplaySpeed,
  benchmarkResult,
  validationReport,
  pcapMessage,
  activeAlerts,
  history,
  resolveAllAlerts,
  clearHistory,
  clearAllData,
}) {
  const detectedAlert = demoCommand
    ? activeAlerts.find(
        (alert) =>
          alert.source_ip === demoCommand.sourceIp &&
          alert.attack_type === demoCommand.attackType
      )
    : null;

  const simulationDetected = Boolean(detectedAlert);

  const [expandedCommandCard, setExpandedCommandCard] = useState(null);

  const toggleCommandCard = (type) => {
    if (expandedCommandCard === type) setExpandedCommandCard(null);
    else setExpandedCommandCard(type);
  };

  const getCommandForType = (type) => {
    if (!demoConfig) return "Loading configuration...";
    const commands = {
      PORT_SCAN: `sudo nmap -sS -Pn -p 20-44 ${demoConfig.target_ip}`,
      SYN_FLOOD: `sudo hping3 -S -p 80 -c 500 -i u1000 ${demoConfig.target_ip}`,
      C2_BEACONING: `for i in {1..5}; do nc -zvw 2 ${demoConfig.target_ip} 8080; sleep 5; done`,
      DGA_DNS_TUNNELLING: `sudo python3 - <<'PY'
from scapy.all import IP, UDP, DNS, DNSQR, send
import random, string, time

for _ in range(10):
    token = ''.join(random.choices(
        string.ascii_lowercase + string.digits, k=32
    ))
    domain = token + ".example.com"

    pkt = (
        IP(src="${demoConfig.source_ip}", dst="${demoConfig.target_ip}") /
        UDP(sport=40000, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=domain))
    )

    send(pkt, iface="eth2", verbose=False)
    time.sleep(0.05)

print("DGA DNS TEST COMPLETE")
PY`,
      TLS_METADATA_ANOMALY: `sudo python3 - <<'PY'
from scapy.all import IP, TCP, send
from scapy.layers.tls.all import TLS, TLSClientHello

pkt = (
    IP(src="${demoConfig.source_ip}", dst="${demoConfig.target_ip}") /
    TCP(sport=44444, dport=8443, flags="PA") /
    TLS(msg=[
        TLSClientHello(
            version=0x0303,
            ciphers=[0x002f]
        )
    ])
)

send(pkt, iface="eth2", verbose=False)
print("SUSPICIOUS TLS CLIENTHELLO SENT")
PY`,
      DATA_EXFILTRATION: `python3 -c "print('A' * 600000)" > /tmp/exfil_test.bin && pv -L 70000 /tmp/exfil_test.bin | nc ${demoConfig.target_ip} 9000`,
    };
    return commands[type] || "Command not defined.";
  };

  const getPcapLabel = (filename) => {
    if (filename === "demo.pcap") return "MONI Threat Validation";
    if (filename === "benign.pcap") return "Benign Traffic Baseline";
    if (filename === "data/benign_lab.pcap") return "Lab Traffic Capture";
    return filename.split("/").pop();
  };

  return (
    <>
      <section className="demo-intro">
        <div>
          <span className="section-kicker">MONI DEMO LAB</span>
          <h2>Prototype Demonstration Engine</h2>
          <p>
            Evaluate MONI's detection pipeline by generating synthetic traffic,
            replaying PCAP captures, and validating ground-truth accuracy.
          </p>
        </div>
      </section>

      <div style={{ padding: '0 24px' }}>
        <DemoPipelineVisualization
          isRunning={simulating !== null || isReplaying || selectedPcap === "live"}
          currentVector={isReplaying ? 'PCAP' : simulating}
          mode={selectedPcap === "live" ? "live" : isReplaying ? "replay" : simulating !== null ? "synthetic" : "idle"}
        />
      </div>

      {/* Synthetic Vectors */}
      <Reveal delay={0.1}>
        <section className="page-section demo-section">
        <div className="section-heading demo-heading">
          <div>
            <span className="section-kicker">LIVE SIMULATION</span>
            <h3>Synthetic Attack Vectors</h3>
          </div>

          <div className="demo-readonly-status">
            <Shield size={17} />
            <span>READ-ONLY DETECTION PATH</span>
          </div>
        </div>

        <div className="demo-vector-grid">
          {DETECTORS_CONFIG
            .filter((det) => det.type !== "ML_ANOMALY")
            .map((det) => {
              const IconComponent = det.icon;
              const isRunning = simulating === det.type;
              const isExpanded = expandedCommandCard === det.type;

              return (
                <div key={det.type} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div
                    className={`demo-vector-btn ${
                      isRunning ? "is-running" : ""
                    }`}
                    style={{ cursor: 'default' }}
                  >
                    <span
                      className="demo-vector-icon"
                      style={{
                        background: `${det.color}15`,
                        color: det.color,
                      }}
                    >
                      <IconComponent size={18} />
                    </span>

                    <span className="demo-vector-copy">
                      <strong>{det.label}</strong>
                      <small>{det.category}</small>
                    </span>

                    <div style={{ display: 'flex', gap: '6px' }}>
                      <button
                        className="demo-secondary-btn"
                        style={{ height: '26px', padding: '0 8px', fontSize: '10px' }}
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleCommandCard(det.type);
                        }}
                      >
                        {isExpanded ? "Hide Cmd" : "View Cmd"}
                      </button>
                      <button
                        className="demo-primary-btn"
                        style={{ height: '26px', padding: '0 8px', fontSize: '10px' }}
                        onClick={(e) => {
                          e.stopPropagation();
                          triggerSimulation(det.type);
                        }}
                        disabled={simulating !== null}
                      >
                        {isRunning ? "Running..." : "Run"}
                      </button>
                    </div>
                  </div>
                  {isExpanded && (
                    <div style={{
                      padding: '12px',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '8px',
                      background: 'var(--bg-tertiary)',
                      fontSize: '11px',
                      marginBottom: '8px'
                    }}>
                       <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', alignItems: 'center' }}>
                         <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Execute on Kali test host:</span>
                         <button
                            className="demo-secondary-btn"
                            style={{ height: '22px', padding: '0 8px', fontSize: '10px' }}
                            onClick={() => navigator.clipboard.writeText(getCommandForType(det.type))}
                         >
                            Copy
                         </button>
                       </div>
                       <textarea
                         value={getCommandForType(det.type)}
                         readOnly
                         style={{
                           width: '100%',
                           minHeight: '60px',
                           padding: '8px',
                           border: '1px solid var(--border-medium)',
                           borderRadius: '4px',
                           background: 'var(--bg-primary)',
                           color: 'var(--text-primary)',
                           fontFamily: 'monospace',
                           fontSize: '11px',
                           resize: 'vertical',
                           lineHeight: '1.4'
                         }}
                       />
                    </div>
                  )}
                </div>
              );
            })}
        </div>
        </section>
      </Reveal>

      {/* Controlled Lab Status */}
      {demoCommand && (
        <Reveal delay={0.15}>
          <section className="page-section demo-section">
            <div className="section-heading">
              <div>
                <span className="section-kicker">CONTROLLED THREAT SIMULATION</span>
                <h3>Passive Lab Traffic</h3>
              </div>

              <span className="section-muted">
                {demoCommand.status === "ERROR"
                  ? "Configuration error"
                  : "Authorized lab workflow"}
              </span>
            </div>

            {demoCommand.status === "ERROR" ? (
              <div className="demo-message">
                <XCircle size={15} />
                <span>{demoCommand.error}</span>
              </div>
            ) : (
              <>
                <div className="demo-kpi-grid">
                  <div className="demo-kpi">
                    <span>SOURCE</span>
                    <strong>{demoCommand.sourceIp}</strong>
                  </div>

                  <div className="demo-kpi">
                    <span>TARGET</span>
                    <strong>{demoCommand.targetIp}</strong>
                  </div>

                  <div className="demo-kpi">
                    <span>SENSOR</span>
                    <strong>{demoCommand.sensorInterface}</strong>
                  </div>

                  <div className="demo-kpi">
                    <span>MODE</span>
                    <strong>{demoCommand.sensorMode}</strong>
                  </div>

                  <div className="demo-kpi">
                    <span>STATUS</span>
                    <strong>{simulationDetected ? "DETECTED" : "READY"}</strong>
                  </div>
                </div>

                <div className="demo-message">
                  {simulationDetected ? (
                    <>
                      <CheckCircle2 size={15} />
                      <span>
                        MONI detected{" "}
                        {demoCommand.attackType.replaceAll("_", " ")} from{" "}
                        {demoCommand.sourceIp}. Confidence:{" "}
                        {Math.round((detectedAlert?.confidence || 0) * 100)}%
                      </span>
                    </>
                  ) : (
                    <>
                      <Shield size={15} />
                      <span>
                        MONI is waiting for passively observed{" "}
                        {demoCommand.attackType.replaceAll("_", " ")} traffic. Run the
                        authorized command on the lab source host.
                      </span>
                    </>
                  )}
                </div>
              </>
            )}
          </section>
        </Reveal>
      )}


      {/* PCAP Replay */}
      <Reveal delay={0.2}>
        <section className="page-section demo-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">
              {selectedPcap === "demo.pcap" ? "THREAT VALIDATION" : selectedPcap === "live" ? "LIVE CAPTURE" : "BENIGN BASELINE"}
            </span>
            <h3>{selectedPcap === "live" ? "Live Sensor Monitoring" : "Streaming Capture Validation"}</h3>
          </div>
          <span className="section-muted">Same 1-second pipeline</span>
        </div>

        <div className="demo-control-row">
          <button
            className="demo-primary-btn"
            onClick={handleGeneratePcap}
            disabled={isGenerating || isReplaying || selectedPcap === "live"}
          >
            <Sparkles size={15} />
            {isGenerating ? "Generating..." : "Generate PCAP"}
          </button>

          <div className="demo-select-group">
            <label>Capture</label>
            <select
              value={selectedPcap}
              onChange={(e) => setSelectedPcap(e.target.value)}
              disabled={isReplaying || isGenerating}
            >
              {pcapFiles.length > 0 ? (
                <>
                  <option value="live">Live Traffic (enp0s8)</option>
                  {pcapFiles
                    .map((file) => typeof file === "string" ? file : file.filename)
                    .filter((filename) => filename !== "data/benign_lab.pcap")
                    .map((filename) => (
                      <option key={filename} value={filename}>
                        {getPcapLabel(filename)}
                      </option>
                    ))}
                </>
              ) : (
                <>
                  <option value="live">Live Traffic (enp0s8)</option>
                  <option value="demo.pcap">MONI Threat Validation</option>
                </>
              )}
            </select>
          </div>

          <div className="demo-select-group">
            <label>Replay Speed</label>
            <select
              value={replaySpeed}
              onChange={(e) => setReplaySpeed(e.target.value)}
              disabled={isReplaying || selectedPcap === "live"}
            >
              <option value="max">Max Benchmark Speed</option>
              <option value="4.0">4x Fast Forward</option>
              <option value="2.0">2x Fast</option>
              <option value="1.0">1x Real-Time</option>
            </select>
          </div>

          {selectedPcap !== "live" && (
            <button
              className="demo-secondary-btn"
              onClick={handleReplayPcap}
              disabled={isReplaying || isGenerating}
            >
              <Play size={15} />
              {isReplaying ? "Streaming..." : "Replay PCAP"}
            </button>
          )}

          {selectedPcap === "demo.pcap" && (
            <button
              className="demo-secondary-btn"
              onClick={handleValidateAccuracy}
              disabled={isValidating || isReplaying}
            >
              <Award size={15} />
              {isValidating ? "Scoring..." : "Evaluate Detection"}
            </button>
          )}
        </div>

        {pcapMessage && (
          <div className="demo-message">
            <Activity size={15} />
            <span>{pcapMessage}</span>
          </div>
        )}
        </section>
      </Reveal>

      {/* Summary and Benchmark */}
      {benchmarkResult && selectedPcap !== "live" && (
        <Reveal delay={0.3}>
          <section className="page-section demo-section">

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
            {/* MONI PROCESSING SUMMARY */}
            <div>
              <div className="section-heading">
                <div>
                  <span className="section-kicker">MONI PROCESSING SUMMARY</span>
                  <h3>Replay Complete</h3>
                </div>
              </div>
              <div className="demo-kpi-grid">
                <div className="demo-kpi">
                  <span>PACKETS IN</span>
                  <strong>{benchmarkResult.packet_count.toLocaleString()}</strong>
                </div>
                <div className="demo-kpi">
                  <span>PACKETS PROCESSED</span>
                  <strong>{benchmarkResult.packet_count.toLocaleString()}</strong>
                </div>
                <div className="demo-kpi">
                  <span>FLOWS OBSERVED</span>
                  <strong>{benchmarkResult.flows_seen.toLocaleString()}</strong>
                </div>
                <div className="demo-kpi">
                  <span>WINDOWS EVALUATED</span>
                  <strong>{benchmarkResult.windows_evaluated?.toLocaleString() || 0}</strong>
                </div>
                <div className="demo-kpi">
                  <span>ALERT EVENTS</span>
                  <strong>{benchmarkResult.alert_events?.toLocaleString() || 0}</strong>
                </div>
              </div>
            </div>

            {/* THROUGHPUT BENCHMARK */}
            <div>
              <div className="section-heading">
                <div>
                  <span className="section-kicker">THROUGHPUT BENCHMARK</span>
                  <h3>Replay Performance</h3>
                </div>
              </div>
              <div className="demo-kpi-grid">
                <div className="demo-kpi">
                  <span>SUSTAINED PACKET RATE</span>
                  <strong>
                    {benchmarkResult.sustained_pps.toFixed(1)}
                    <small> pkt/s</small>
                  </strong>
                </div>
                <div className="demo-kpi highlight">
                  <span>THROUGHPUT</span>
                  <strong>
                    {benchmarkResult.sustained_mbps.toFixed(2)}
                    <small> Mbps</small>
                  </strong>
                </div>
                <div className="demo-kpi">
                  <span>FLOW RATE</span>
                  <strong>
                    {benchmarkResult.flow_rate.toFixed(1)}
                    <small> flows/s</small>
                  </strong>
                </div>
                <div className="demo-kpi">
                  <span>REPLAY DURATION</span>
                  <strong>{benchmarkResult.wall_elapsed.toFixed(2)}s</strong>
                </div>
              </div>
            </div>
          </div>

          </section>
        </Reveal>
      )}

      {/* Accuracy */}
      {validationReport && selectedPcap === "demo.pcap" && (
        <Reveal delay={0.4}>
          <section className="page-section demo-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">GROUND-TRUTH VALIDATION</span>
              <h3>Detection Accuracy</h3>
            </div>
            <span className="section-muted">PCAP manifest comparison</span>
          </div>

          <div className="demo-score-grid">
            <div>
              <span>RECALL</span>
              <strong>
                {((validationReport.recall || 0) * 100).toFixed(0)}%
              </strong>
            </div>

            <div>
              <span>PRECISION</span>
              <strong>
                {((validationReport.precision || 0) * 100).toFixed(1)}%
              </strong>
            </div>

            <div>
              <span>F1 SCORE</span>
              <strong>
                {((validationReport.f1 || 0) * 100).toFixed(1)}%
              </strong>
            </div>
          </div>

          <div className="demo-validation-table">
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Threat Class</th>
                  <th>Result</th>
                  <th>Confidence</th>
                </tr>
              </thead>

              <tbody>
                {validationReport.detailed_results?.map((item, idx) => (
                  <tr key={idx}>
                    <td>{item.source_ip}</td>
                    <td>{item.attack_type}</td>
                    <td>
                      {item.caught ? (
                        <span className="demo-caught">
                          <CheckCircle2 size={12} />
                          CAUGHT
                        </span>
                      ) : (
                        <span className="demo-missed">
                          <XCircle size={12} />
                          MISSED
                        </span>
                      )}
                    </td>
                    <td>
                      {item.caught
                        ? `${Math.round(item.confidence * 100)}%`
                        : "--"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          </section>
        </Reveal>
      )}

      {/* Lab Controls */}
      <Reveal delay={0.5}>
        <section className="page-section demo-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">LAB CONTROLS</span>
            <h3>Incident State Management</h3>
          </div>
          <span className="section-muted">
            {activeAlerts.length} active · {history.length} recorded
          </span>
        </div>

        <div className="demo-management-row">
          <button
            className="demo-secondary-btn"
            onClick={resolveAllAlerts}
            disabled={simulating !== null || activeAlerts.length === 0}
          >
            <RotateCcw size={14} />
            Resolve Active
          </button>

          <button
            className="demo-secondary-btn"
            onClick={clearHistory}
            disabled={simulating !== null || history.length === 0}
          >
            <Trash2 size={14} />
            Clear History
          </button>

          <button
            className="demo-reset-btn"
            onClick={clearAllData}
            disabled={simulating !== null}
          >
            <RotateCcw size={14} />
            Reset System
          </button>
        </div>
        </section>
      </Reveal>
    </>
  );
}
