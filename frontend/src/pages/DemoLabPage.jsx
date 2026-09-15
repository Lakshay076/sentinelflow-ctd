import React from "react";
import { Shield, Sparkles, Play, Award, Activity, CheckCircle2, XCircle, RotateCcw, Trash2 } from "lucide-react";
import { DETECTORS_CONFIG } from "../config";
import { DemoPipelineVisualization } from "../components/DemoPipelineVisualization";
import { Reveal } from "../components/Reveal";

export function DemoLabPage({
  simulating,
  triggerSimulation,
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
          isRunning={simulating !== null || isReplaying} 
          currentVector={isReplaying ? 'PCAP' : simulating} 
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

              return (
                <button
                  key={det.type}
                  className={`demo-vector-btn ${
                    isRunning ? "is-running" : ""
                  }`}
                  onClick={() => triggerSimulation(det.type)}
                  disabled={simulating !== null}
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

                  <span className="demo-vector-action">
                    {isRunning ? "Running..." : "Run"}
                  </span>
                </button>
              );
            })}
        </div>
        </section>
      </Reveal>

      {/* PCAP Replay */}
      <Reveal delay={0.2}>
        <section className="page-section demo-section">
        <div className="section-heading">
          <div>
            <span className="section-kicker">PCAP REPLAY</span>
            <h3>Streaming Capture Validation</h3>
          </div>
          <span className="section-muted">Same 1-second pipeline</span>
        </div>

        <div className="demo-control-row">
          <button
            className="demo-primary-btn"
            onClick={handleGeneratePcap}
            disabled={isGenerating || isReplaying}
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
                pcapFiles.map((file) => {
                  const filename =
                    typeof file === "string" ? file : file.filename;

                  return (
                    <option key={filename} value={filename}>
                      {filename}
                    </option>
                  );
                })
              ) : (
                <option value="demo.pcap">demo.pcap</option>
              )}
            </select>
          </div>

          <div className="demo-select-group">
            <label>Replay Speed</label>
            <select
              value={replaySpeed}
              onChange={(e) => setReplaySpeed(e.target.value)}
              disabled={isReplaying}
            >
              <option value="max">Max Benchmark Speed</option>
              <option value="4.0">4x Fast Forward</option>
              <option value="2.0">2x Fast</option>
              <option value="1.0">1x Real-Time</option>
            </select>
          </div>

          <button
            className="demo-secondary-btn"
            onClick={handleReplayPcap}
            disabled={isReplaying || isGenerating}
          >
            <Play size={15} />
            {isReplaying ? "Streaming..." : "Replay PCAP"}
          </button>

          <button
            className="demo-secondary-btn"
            onClick={handleValidateAccuracy}
            disabled={isValidating || isReplaying}
          >
            <Award size={15} />
            {isValidating ? "Scoring..." : "Score Accuracy"}
          </button>
        </div>

        {pcapMessage && (
          <div className="demo-message">
            <Activity size={15} />
            <span>{pcapMessage}</span>
          </div>
        )}
        </section>
      </Reveal>

      {/* Benchmark */}
      {benchmarkResult && (
        <Reveal delay={0.3}>
          <section className="page-section demo-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">THROUGHPUT BENCHMARK</span>
              <h3>Replay Performance</h3>
            </div>
            <span className="section-muted">Measured pipeline output</span>
          </div>

          <div className="demo-kpi-grid">
            <div className="demo-kpi">
              <span>PACKETS PROCESSED</span>
              <strong>
                {benchmarkResult.packet_count.toLocaleString()}
              </strong>
            </div>

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
              <span>OBSERVED FLOWS</span>
              <strong>
                {benchmarkResult.flows_seen.toLocaleString()}
                <small> ({benchmarkResult.flow_rate.toFixed(1)}/s)</small>
              </strong>
            </div>

            <div className="demo-kpi">
              <span>REPLAY DURATION</span>
              <strong>{benchmarkResult.wall_elapsed.toFixed(2)}s</strong>
            </div>
          </div>
          </section>
        </Reveal>
      )}

      {/* Accuracy */}
      {validationReport && (
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
