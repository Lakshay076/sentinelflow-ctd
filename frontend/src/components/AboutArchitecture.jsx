import React from "react";
import { ArrowDown } from "lucide-react";

export function AboutArchitecture() {
  return (
    <div className="about-architecture">
      <div className="arch-node">
        <strong>Passive Traffic Ingest</strong>
      </div>
      <div className="arch-arrow">
        <ArrowDown size={16} />
      </div>

      <div className="arch-node">
        <strong>Streaming Feature Engine</strong>
      </div>
      <div className="arch-arrow">
        <ArrowDown size={16} />
      </div>

      <div className="arch-layer">
        <div className="arch-layer-header">
          <strong>Detection Layer</strong>
        </div>
        <div className="arch-branches">
          <div className="arch-branch">
            <div className="arch-branch-line" />
            <div className="arch-arrow">
              <ArrowDown size={16} />
            </div>
            <div className="arch-node">
              <strong>Rule-Based Detectors</strong>
              <ul>
                <li>SYN Flood</li>
                <li>Port Scanning</li>
                <li>C2 Beaconing</li>
                <li>DGA / DNS Tunnelling</li>
                <li>TLS Metadata Anomaly</li>
                <li>Data Exfiltration</li>
              </ul>
            </div>
          </div>
          
          <div className="arch-branch">
            <div className="arch-branch-line" />
            <div className="arch-arrow">
              <ArrowDown size={16} />
            </div>
            <div className="arch-node">
              <strong>ML Anomaly Detector</strong>
              <p>Provides anomaly and corroborating evidence based on behavioral features.</p>
            </div>
          </div>

          <div className="arch-branch">
            <div className="arch-branch-line" />
            <div className="arch-arrow">
              <ArrowDown size={16} />
            </div>
            <div className="arch-node future">
              <strong>Supervised Classifier</strong>
              <span className="arch-badge">Planned / Research Phase</span>
            </div>
          </div>
        </div>
      </div>

      <div className="arch-arrow">
        <ArrowDown size={16} />
      </div>

      <div className="arch-node">
        <strong>Detection Evidence</strong>
      </div>
      <div className="arch-arrow">
        <ArrowDown size={16} />
      </div>

      <div className="arch-node">
        <strong>Incident Correlation</strong>
      </div>
      <div className="arch-arrow">
        <ArrowDown size={16} />
      </div>

      <div className="arch-node active">
        <strong>Explainable Alert</strong>
      </div>
      
      <div className="arch-spacer" />
      
      <div className="arch-system-stack">
        <div className="arch-node"><strong>Alert Manager</strong></div>
        <div className="arch-arrow"><ArrowDown size={16} /></div>
        <div className="arch-node"><strong>PostgreSQL</strong></div>
        <div className="arch-arrow"><ArrowDown size={16} /></div>
        <div className="arch-node"><strong>FastAPI</strong></div>
        <div className="arch-arrow"><ArrowDown size={16} /></div>
        <div className="arch-node active"><strong>MONI Dashboard</strong></div>
      </div>
    </div>
  );
}
