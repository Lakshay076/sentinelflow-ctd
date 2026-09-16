import React from "react";
import { Activity, AlertTriangle, CheckCircle, Gauge } from "lucide-react";
import { StatCard } from "../components/StatCard";
import { DETECTORS_CONFIG } from "../config";
import { motion } from "framer-motion";
import { AttackClassChart } from "../components/AttackClassChart";

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.08 }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.4, ease: "easeOut" } }
};

export function OverviewPage({
  lastUpdated,
  stats,
  liveMetrics,
  activeAlerts,
  history,
  filterType,
  setFilterType,
}) {
  return (
    <div className="overview-page-wrapper">
      {/* SECTION 1: Base Neutral */}
      <motion.section
        className="overview-section section-base"
        initial={{ opacity: 0, y: 15 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-40px" }}
        transition={{ duration: 0.5 }}
      >
        <div className="page-heading">
          <div>
            <h2>Threat Matrix & Ingest Benchmarking</h2>
            <p>
              Passive streaming threat detection across 7 specialized rule & AI
              detectors with verified ground truth accuracy.
            </p>
          </div>
        </div>

        <motion.div
          className="stats-grid"
          variants={containerVariants}
          initial="hidden"
          animate="visible"
        >
          <motion.div variants={itemVariants}>
            <StatCard
              icon={<Activity size={22} />}
              label="Total Incidents"
              value={stats?.total_alerts ?? 0}
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <StatCard
              icon={<AlertTriangle size={22} />}
              label="Active Threats"
              value={stats?.active_alerts ?? 0}
              danger={stats?.active_alerts > 0}
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <StatCard
              icon={<CheckCircle size={22} />}
              label="Resolved Alerts"
              value={stats?.resolved_alerts ?? 0}
            />
          </motion.div>
          <motion.div variants={itemVariants}>
              <StatCard
                icon={<Gauge size={22} />}
                label="Throughput"
                value={
                  liveMetrics?.latest?.mbps != null
                    ? `${liveMetrics.latest.mbps.toFixed(2)} Mbps`
                    : "Awaiting Ingest"
                }
                highlight={liveMetrics?.latest?.mbps != null}
              />
          </motion.div>
        </motion.div>
      </motion.section>

      {/* SECTION 2: Alternate Surface */}
      <motion.section
        className="overview-section section-alt detector-matrix-section"
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-40px" }}
        transition={{ duration: 0.5 }}
      >
        <div className="section-header">
          <div>
            <h3>Armed Threat Detectors</h3>
            <p>Specialized heuristic engines & unsupervised AI model status</p>
          </div>
        </div>
        <motion.div
          className="detectors-grid"
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-40px" }}
        >
          {DETECTORS_CONFIG.map((det) => {
            const IconComponent = det.icon;
            const count = stats?.attack_types?.[det.type] ?? 0;
            const hasActive = activeAlerts.some(
              (a) => a.attack_type === det.type
            );

            return (
              <motion.div
                key={det.type}
                variants={itemVariants}
                className={`detector-card ${hasActive ? "has-active" : ""}`}
                onClick={() =>
                  setFilterType(filterType === det.type ? "ALL" : det.type)
                }
                title="Click to filter by this attack type"
              >
                <div className="detector-card-top">
                  <div
                    className="detector-icon-wrapper"
                    style={{
                      background: `${det.color}15`,
                      color: det.color,
                    }}
                  >
                    <IconComponent size={20} />
                  </div>
                  <span
                    className={`detector-status-pill ${
                      hasActive ? "pill-danger" : "pill-online"
                    }`}
                  >
                    {hasActive ? "DETECTED" : "ARMED"}
                  </span>
                </div>

                <h4>{det.label}</h4>
                <p>{det.description}</p>

                <div className="detector-card-bottom">
                  <span>Incidents</span>
                  <strong>{count}</strong>
                </div>
              </motion.div>
            );
          })}
        </motion.div>
      </motion.section>

      {/* SECTION 3: Threat Landscape */}
      <motion.section
        className="overview-section section-tint attack-summary"
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-40px" }}
        transition={{ duration: 0.5 }}
      >
        <div className="section-header">
          <div>
            <h3>Attack Class Breakdown</h3>
            <p>Distribution of identified threats by vector</p>
          </div>
        </div>
        <AttackClassChart stats={stats} historyLength={history.length} />
      </motion.section>
    </div>
  );
}
