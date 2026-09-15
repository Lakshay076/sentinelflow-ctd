import React from "react";
import { Radio, Lock, BrainCircuit, Activity, Shield, Globe, ArrowRight, ArrowDown } from "lucide-react";
import { Reveal } from "../components/Reveal";
import { AboutArchitecture } from "../components/AboutArchitecture";
import { AboutBackground } from "../components/AboutBackground";

export function AboutMoniPage() {
  const threats = [
    { name: "Volumetric / Protocol DDoS", desc: "Unusually high flow rates or packet counts dominating the link." },
    { name: "Botnet C2 Beaconing", desc: "Regular, periodic small-payload connections to external destinations." },
    { name: "DGA and DNS Tunnelling", desc: "High entropy or structurally anomalous DNS queries and large TXT records." },
    { name: "TLS Metadata Anomalies", desc: "Suspicious cipher suites, mismatched SNI, or rare TLS extensions." },
    { name: "Reconnaissance and Port Scanning", desc: "Rapid traversal of destination ports or IP sweeps." },
    { name: "Suspicious Data Exfiltration", desc: "Asymmetric outbound heavy transfers following internal access." },
  ];

  return (
    <div className="about-moni-page">
      <AboutBackground />
      <div className="about-moni-content">
        {/* 01 - HERO / WHAT IS MONI? */}
      <section className="about-hero">
        <div className="about-hero-copy">
          <span className="section-kicker">CYBER THREAT DETECTION</span>
          <h2>MONI turns passive traffic into actionable security intelligence.</h2>
          <p>
            MONI is a passive cyber threat detection platform designed for environments where network traffic can be observed through a passive one-directional copy, but the monitoring system must not interfere with production operations.
          </p>
        </div>

        <div className="about-hero-status">
          <Shield size={24} />
          <div>
            <strong>PASSIVE SENSOR</strong>
            <span>Read-only observation architecture</span>
          </div>
        </div>
      </section>

      {/* 02 - WHY MONI? */}
      <Reveal delay={0.1}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">THE PROBLEM</span>
              <h3>Why MONI?</h3>
            </div>
          </div>
          <div className="about-why">
            <div className="why-diagram">
              <div className="why-node prod">PRODUCTION NETWORK</div>
              <div className="why-arrow"><div className="line"/><ArrowRight size={16}/><span>Passive traffic copy</span></div>
              <div className="why-node moni">MONI SENSOR</div>
              <div className="why-arrow"><div className="line"/><ArrowRight size={16}/></div>
              <div className="why-node intel">Security Intelligence</div>
            </div>
            <div className="why-text">
              <ul>
                <li>MONI observes traffic rather than controlling it.</li>
                <li>There is no return path into production.</li>
                <li>Detection is based on packets, flows, and derived metadata.</li>
                <li>Application payloads are not decrypted.</li>
              </ul>
            </div>
          </div>
        </section>
      </Reveal>

      {/* 03 - MONI ARCHITECTURE */}
      <Reveal delay={0.2}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">SYSTEM DESIGN</span>
              <h3>MONI Architecture</h3>
            </div>
            <span className="section-muted">From traffic copy to security alert</span>
          </div>
          <AboutArchitecture />
        </section>
      </Reveal>

      {/* 04 - HOW DETECTION WORKS */}
      <Reveal delay={0.3}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">INTELLIGENCE PIPELINE</span>
              <h3>How Detection Works</h3>
            </div>
          </div>
          <div className="about-pipeline-overview">
            <div className="pipeline-flow">
              <span>Packets</span><ArrowRight size={14}/>
              <span>Flows</span><ArrowRight size={14}/>
              <span>Streaming windows</span><ArrowRight size={14}/>
              <span>Behavioral features</span><ArrowRight size={14}/>
              <span>Rule detectors + ML anomaly analysis</span><ArrowRight size={14}/>
              <span>Correlation</span><ArrowRight size={14}/>
              <span className="highlight">Incident</span>
            </div>
            
            <div className="about-features-grid">
              <div className="feature-card">
                <h4>Network</h4>
                <ul><li>packets/sec</li><li>bytes/sec</li><li>flows/sec</li></ul>
              </div>
              <div className="feature-card">
                <h4>TCP</h4>
                <ul><li>SYN ratio</li><li>SYN rate</li><li>TCP flags</li></ul>
              </div>
              <div className="feature-card">
                <h4>Recon</h4>
                <ul><li>destination-port diversity</li><li>flow rate</li><li>destination diversity</li></ul>
              </div>
              <div className="feature-card">
                <h4>Temporal</h4>
                <ul><li>connection intervals</li><li>timing regularity</li></ul>
              </div>
              <div className="feature-card">
                <h4>DNS</h4>
                <ul><li>entropy</li><li>domain length</li><li>unique domains</li><li>query rate</li></ul>
              </div>
              <div className="feature-card">
                <h4>TLS</h4>
                <ul><li>cipher-suite metadata</li><li>extension metadata</li><li>SNI presence</li></ul>
              </div>
            </div>
          </div>
        </section>
      </Reveal>

      {/* 05 - EXPLAINABLE DETECTION */}
      <Reveal delay={0.4}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">INCIDENT CORRELATION</span>
              <h3>Explainable Detection</h3>
            </div>
          </div>
          <div className="about-explainable">
            <p className="explain-intro">
              MONI does not simply output "THREAT DETECTED". Instead, an incident contains rich context allowing a SOC analyst to understand <em>why</em> an alert was fired.
            </p>
            <div className="incident-mockup">
              <div className="mockup-header">
                <span className="mockup-sev high">HIGH</span>
                <strong>Botnet C2 Beaconing</strong>
              </div>
              <div className="mockup-body">
                <div className="mockup-row"><span>Source IP:</span> 192.168.1.45</div>
                <div className="mockup-row"><span>Confidence:</span> 94%</div>
                <div className="mockup-row"><span>Timestamp:</span> 2026-09-15 10:45:00 UTC</div>
                <div className="mockup-row"><span>Initiator Context:</span> Internal Workstation</div>
                <div className="mockup-evidence">
                  <strong>Supporting Evidence:</strong>
                  <ul>
                    <li>Periodic 5-minute connections (variance &lt; 2s)</li>
                    <li>Low payload variance (48 bytes)</li>
                    <li>Suspicious external ASN</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </section>
      </Reveal>

      {/* 06 - THREAT COVERAGE */}
      <Reveal delay={0.5}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">THREAT COVERAGE</span>
              <h3>What MONI Detects</h3>
            </div>
            <span className="section-muted">Current prototype demonstrated classes</span>
          </div>

          <div className="about-threats">
            {threats.map((threat, index) => (
              <div className="about-threat" key={threat.name}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <div>
                  <strong>{threat.name}</strong>
                  <p>{threat.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>
      </Reveal>

      {/* 07 - SECURITY PRINCIPLES */}
      <Reveal delay={0.6}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">DESIGN PRINCIPLES</span>
              <h3>Security Principles</h3>
            </div>
          </div>

          <div className="about-principles">
            <article className="about-principle">
              <div className="about-principle-icon"><Radio size={18} /></div>
              <div>
                <h4>PASSIVE BY DESIGN</h4>
                <p>MONI observes traffic without controlling production traffic.</p>
              </div>
            </article>
            <article className="about-principle">
              <div className="about-principle-icon"><Lock size={18} /></div>
              <div>
                <h4>NO PAYLOAD DECRYPTION</h4>
                <p>Encrypted sessions are analyzed through observable metadata and behavior.</p>
              </div>
            </article>
            <article className="about-principle">
              <div className="about-principle-icon"><BrainCircuit size={18} /></div>
              <div>
                <h4>NO PROBING</h4>
                <p>MONI does not actively probe monitored systems.</p>
              </div>
            </article>
            <article className="about-principle">
              <div className="about-principle-icon"><Shield size={18} /></div>
              <div>
                <h4>NO INLINE BLOCKING</h4>
                <p>MONI is detection/intelligence infrastructure, not an inline prevention device.</p>
              </div>
            </article>
            <article className="about-principle">
              <div className="about-principle-icon"><Activity size={18} /></div>
              <div>
                <h4>NEAR REAL-TIME</h4>
                <p>Streaming windows allow incremental behavioral evaluation.</p>
              </div>
            </article>
          </div>
        </section>
      </Reveal>

      {/* 08 - DEPLOYMENT MODEL */}
      <Reveal delay={0.7}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">DEPLOYMENT</span>
              <h3>Deployment Model</h3>
            </div>
          </div>

          <div className="about-deployment">
            <div className="about-deployment-path">
              <div className="deployment-node prod">
                <Globe size={17} />
                <strong>PRODUCTION NETWORK</strong>
                <span>Remains isolated</span>
              </div>

              <div className="deployment-connector vertical">
                <ArrowDown size={14} />
                <span>Passive Copy / Mirror</span>
                <div />
              </div>

              <div className="deployment-node active">
                <Shield size={17} />
                <strong>MONI SENSOR (READ-ONLY)</strong>
                <div className="sensor-internals">
                  <span>↓ Feature Engine</span>
                  <span>↓ Detection + Correlation</span>
                  <span>↓ SOC Dashboard</span>
                </div>
              </div>
            </div>

            <div className="about-deployment-note">
              <Lock size={16} />
              <p>
                Supported conceptual observation sources: TAP, SPAN / mirror port, Hardware data diode receiver, NetFlow / IPFIX / sFlow.
              </p>
            </div>
          </div>
        </section>
      </Reveal>

      {/* 09 - FUTURE ROADMAP */}
      <Reveal delay={0.8}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">ROADMAP</span>
              <h3>Future Roadmap</h3>
            </div>
          </div>
          
          <div className="roadmap-grid">
            <div className="roadmap-col current">
              <h4>CURRENT</h4>
              <ul>
                <li>Streaming passive collector</li>
                <li>Six threat detectors</li>
                <li>ML anomaly corroboration</li>
                <li>Incident correlation</li>
                <li>PostgreSQL persistence</li>
                <li>FastAPI</li>
                <li>SOC dashboard</li>
                <li>Controlled PCAP/replay validation</li>
              </ul>
            </div>
            
            <div className="roadmap-col next">
              <h4>NEXT</h4>
              <ul>
                <li>Train supervised classifier using research-grade cybersecurity datasets (UNSW-NB15, CIC-IDS2017)</li>
                <li>Feature normalization</li>
                <li>Train/validation/test pipeline</li>
                <li>Confidence calibration</li>
                <li>Rule + anomaly + supervised fusion</li>
                <li>Formal throughput/latency benchmark</li>
              </ul>
            </div>
            
            <div className="roadmap-col future">
              <h4>FUTURE</h4>
              <ul>
                <li>JA3 / JA3S / JA4-compatible metadata</li>
                <li>QUIC metadata analysis</li>
                <li>DGA sequence models</li>
                <li>Advanced C2 temporal models</li>
                <li>Concept-drift monitoring</li>
                <li>Adversarial robustness testing</li>
                <li>Physical TAP / SPAN / data-diode deployment</li>
                <li>High-speed production benchmarking</li>
              </ul>
            </div>
          </div>
        </section>
      </Reveal>

      {/* 10 - CLOSING STATEMENT */}
      <Reveal delay={0.9}>
        <section className="about-footer-note">
          <div>
            <span className="section-kicker">SIH26145</span>
            <h3>AI-Based Detection of Cyber Threats in Unidirectional IP Traffic</h3>
            <p>
              MONI is designed to turn one-way network visibility into explainable, near-real-time cyber intelligence — without creating a path back into the protected environment.
            </p>
          </div>

          <div className="about-footer-badge">
            <Shield size={20} />
            <span>MONI</span>
          </div>
        </section>
      </Reveal>
      </div>
    </div>
  );
}
