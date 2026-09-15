import React, { useMemo } from "react";
import { 
  Shield, Activity, Gauge, Clock, Globe, Lock, 
  ArrowRight, ArrowDown, Server
} from "lucide-react";
import { Reveal } from "../components/Reveal";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { formatAttackType } from "../utils";

export function ThreatIntelligencePage({ activeAlerts, history }) {
  const allIncidents = [...activeAlerts, ...history];

  const activeSources = [...new Set(
    activeAlerts.map((alert) => alert.source_ip).filter(Boolean)
  )];

  // Threat Definitions & Data for Recharts
  const threatDefinitions = [
    { type: "SYN_FLOOD", label: "SYN Flood" },
    { type: "PORT_SCAN", label: "Port Scanning" },
    { type: "C2_BEACONING", label: "C2 Beaconing" },
    { type: "DGA_DNS_TUNNELLING", label: "DGA / DNS Tunnelling" },
    { type: "TLS_METADATA_ANOMALY", label: "TLS Metadata Anomaly" },
    { type: "DATA_EXFILTRATION", label: "Data Exfiltration" },
  ];

  const chartData = useMemo(() => {
    return threatDefinitions.map(def => {
      const count = allIncidents.filter(inc => inc.attack_type === def.type).length;
      return {
        name: def.label,
        count: count
      };
    }).sort((a, b) => b.count - a.count); // sort descending
  }, [allIncidents]);

  const hasData = allIncidents.length > 0;

  return (
    <div className="intel-page-container">
      {/* 1. HERO */}
      <section className="intel-hero-section">
        <div className="intel-hero-copy">
          <span className="section-kicker">PASSIVE NETWORK INTELLIGENCE</span>
          <h2>MONI converts observed network behaviour into threat intelligence without probing, blocking, or decrypting application payloads.</h2>
        </div>
        <div className="intel-status">
          <Shield size={20} />
          <div>
            <strong>READ-ONLY</strong>
            <span>Passive observation active</span>
          </div>
        </div>
      </section>

      {/* 2. THREAT LANDSCAPE */}
      <Reveal delay={0.1}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">LANDSCAPE</span>
              <h3>Threat Landscape</h3>
            </div>
          </div>
          
          <div className="intel-landscape">
            <div className="landscape-kpis">
              <div className="landscape-kpi">
                <span>Threat Classes</span>
                <strong>{threatDefinitions.length}</strong>
              </div>
              <div className="landscape-kpi">
                <span>Active Threats</span>
                <strong className={activeAlerts.length > 0 ? "danger" : ""}>{activeAlerts.length}</strong>
              </div>
              <div className="landscape-kpi">
                <span>Observed Sources</span>
                <strong>{activeSources.length}</strong>
              </div>
              <div className="landscape-kpi">
                <span>Recorded Incidents</span>
                <strong>{allIncidents.length}</strong>
              </div>
            </div>

            <div className="landscape-chart">
              {!hasData ? (
                <div className="intel-empty-state">
                  <Shield size={24} />
                  <p>No threat data has been recorded yet.</p>
                </div>
              ) : (
                <div style={{ width: '100%', height: 280 }}>
                  <ResponsiveContainer>
                    <BarChart
                      data={chartData}
                      layout="vertical"
                      margin={{ top: 10, right: 30, left: 40, bottom: 0 }}
                    >
                      <XAxis type="number" hide />
                      <YAxis 
                        dataKey="name" 
                        type="category" 
                        axisLine={false} 
                        tickLine={false} 
                        tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                        width={140}
                      />
                      <Tooltip 
                        cursor={{fill: 'var(--bg-tertiary)'}}
                        contentStyle={{ backgroundColor: 'var(--surface-card)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}
                        itemStyle={{ color: 'var(--text-primary)', fontSize: 12 }}
                      />
                      <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={24}>
                        {chartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill="var(--brand-violet)" fillOpacity={0.8 + (index * 0.05)} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          </div>
        </section>
      </Reveal>

      {/* 3. DETECTION INTELLIGENCE (DOMAINS) */}
      <Reveal delay={0.2}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">OBSERVABILITY</span>
              <h3>Detection Intelligence</h3>
            </div>
            <span className="section-muted">Types of behavioural evidence MONI uses</span>
          </div>

          <div className="intel-domains">
            <div className="domain-panel">
              <div className="domain-header"><Activity size={16}/><h4>NETWORK BEHAVIOUR</h4></div>
              <ul>
                <li>Packets/sec</li><li>Bytes/sec</li><li>Flows/sec</li>
                <li>SYN ratio</li><li>SYN rate</li><li>Flow creation rate</li>
                <li>Destination diversity</li><li>Port diversity</li>
              </ul>
            </div>
            <div className="domain-panel">
              <div className="domain-header"><Clock size={16}/><h4>TEMPORAL BEHAVIOUR</h4></div>
              <ul>
                <li>Connection intervals</li><li>Timing variation</li>
                <li>Repeated destinations</li><li>Regular check-in patterns</li>
              </ul>
            </div>
            <div className="domain-panel">
              <div className="domain-header"><Globe size={16}/><h4>DNS INTELLIGENCE</h4></div>
              <ul>
                <li>Domain entropy</li><li>Domain length</li>
                <li>Unique domains</li><li>Query rate</li><li>High-entropy ratio</li>
              </ul>
            </div>
            <div className="domain-panel">
              <div className="domain-header"><Lock size={16}/><h4>ENCRYPTED SESSION METADATA</h4></div>
              <ul>
                <li>TLS cipher-suite metadata</li><li>TLS extension metadata</li>
                <li>SNI presence</li><li>Packet-size/timing behaviour</li>
              </ul>
            </div>
            <div className="domain-panel">
              <div className="domain-header"><Server size={16}/><h4>TRANSFER BEHAVIOUR</h4></div>
              <ul>
                <li>Outbound bytes</li><li>Inbound bytes</li>
                <li>Outbound/inbound ratio</li><li>Sustained transfer rate</li><li>Packet volume</li>
              </ul>
            </div>
          </div>
        </section>
      </Reveal>

      {/* 4. THREAT COVERAGE */}
      <Reveal delay={0.3}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">COVERAGE</span>
              <h3>Threat Coverage</h3>
            </div>
          </div>
          
          <div className="intel-coverage-matrix">
            <div className="coverage-row header">
              <div>Threat</div>
              <div>What MONI observes</div>
              <div>Primary evidence</div>
            </div>
            <div className="coverage-row">
              <div><strong>SYN Flood</strong></div>
              <div>High-rate volumetric flooding</div>
              <div>High SYN ratio, SYN rate, flow creation rate</div>
            </div>
            <div className="coverage-row">
              <div><strong>Port Scanning</strong></div>
              <div>Multi-port reconnaissance</div>
              <div>Destination-port diversity, rapid flow creation, SYN behaviour</div>
            </div>
            <div className="coverage-row">
              <div><strong>C2 Beaconing</strong></div>
              <div>Suspicious periodic check-ins</div>
              <div>Repeated destinations, connection intervals, timing regularity</div>
            </div>
            <div className="coverage-row">
              <div><strong>DGA / DNS Tunnelling</strong></div>
              <div>Algorithmic or tunneling queries</div>
              <div>Domain entropy, length, uniqueness, query behaviour</div>
            </div>
            <div className="coverage-row">
              <div><strong>TLS Metadata Anomaly</strong></div>
              <div>Unusual encrypted sessions</div>
              <div>Cipher-suite count, extension metadata, SNI behaviour</div>
            </div>
            <div className="coverage-row">
              <div><strong>Data Exfiltration</strong></div>
              <div>Asymmetric data transfer</div>
              <div>Outbound volume, directional asymmetry, sustained transfer rate</div>
            </div>
          </div>
        </section>
      </Reveal>

      {/* 5. INTELLIGENCE PIPELINE */}
      <Reveal delay={0.4}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">PIPELINE</span>
              <h3>Intelligence Pipeline</h3>
            </div>
          </div>
          
          <div className="intel-pipeline-flow">
            <div className="pipe-node">OBSERVED PACKETS</div>
            <ArrowRight size={16} />
            <div className="pipe-node">FLOW RECORDS</div>
            <ArrowRight size={16} />
            <div className="pipe-node">STREAMING WINDOWS</div>
            <ArrowRight size={16} />
            <div className="pipe-node">BEHAVIOURAL FEATURES</div>
            <ArrowRight size={16} />
            <div className="pipe-node stacked">
              <span>RULE DETECTORS + ML ANOMALY</span>
              <span className="pipe-future">Supervised Classifier (Planned research phase)</span>
            </div>
            <ArrowRight size={16} />
            <div className="pipe-node">CORRELATION</div>
            <ArrowRight size={16} />
            <div className="pipe-node highlight">EXPLAINABLE INCIDENT</div>
          </div>
        </section>
      </Reveal>

      {/* 6. EVIDENCE -> DECISION */}
      <Reveal delay={0.5}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">EXPLAINABILITY</span>
              <h3>Evidence → Decision</h3>
            </div>
          </div>
          
          <div className="intel-decision-flow">
            <div className="decision-step">
              <span>OBSERVATION</span>
              <p>"SYN activity across many destination ports"</p>
            </div>
            <ArrowDown size={16} />
            <div className="decision-step">
              <span>FEATURES</span>
              <p>"Port diversity + flow rate + SYN ratio"</p>
            </div>
            <ArrowDown size={16} />
            <div className="decision-step">
              <span>DETECTION</span>
              <p>"Port Scanning"</p>
            </div>
            <ArrowDown size={16} />
            <div className="decision-step">
              <span>CORRELATION</span>
              <p>"Related behavioural evidence"</p>
            </div>
            <ArrowDown size={16} />
            <div className="decision-step highlight">
              <span>OUTPUT</span>
              <p>"Structured security incident"</p>
            </div>
          </div>
        </section>
      </Reveal>

      {/* 7. RESEARCH / FUTURE INTELLIGENCE */}
      <Reveal delay={0.6}>
        <section className="page-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">ROADMAP</span>
              <h3>Next Intelligence Layer</h3>
            </div>
          </div>
          
          <div className="future-intel-list">
            <div className="future-col">
              <h4>NEXT</h4>
              <ul>
                <li>Supervised cybersecurity classifier</li>
                <li>Research-grade dataset training</li>
                <li>Confidence calibration</li>
                <li>Rule + anomaly + supervised fusion</li>
              </ul>
            </div>
            <div className="future-col">
              <h4>FUTURE</h4>
              <ul>
                <li>JA3 / JA3S / JA4-compatible metadata</li>
                <li>QUIC metadata analysis</li>
                <li>Advanced C2 temporal modelling</li>
                <li>DGA sequence modelling</li>
                <li>Concept-drift monitoring</li>
                <li>Adversarial robustness</li>
              </ul>
            </div>
          </div>
        </section>
      </Reveal>
    </div>
  );
}
