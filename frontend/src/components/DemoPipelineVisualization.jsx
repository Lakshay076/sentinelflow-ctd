import React from 'react';
import { motion } from 'framer-motion';
import { Network, ShieldAlert, Database } from 'lucide-react';

export function DemoPipelineVisualization({ isRunning, currentVector, mode }) {
  const isSimulating = Boolean(isRunning || currentVector);

  let sourceLabel = 'Network Source';
  if (mode === 'live') {
    sourceLabel = 'Live Sensor (enp0s8)';
  } else if (mode === 'replay') {
    sourceLabel = 'PCAP Reader';
  } else if (currentVector) {
    sourceLabel = 'Simulated Vector';
  }

  const Connector = ({ delay = 0, baseColor, activeColor }) => (
    <div style={{ flex: 1, height: '4px', background: baseColor, borderRadius: '2px', position: 'relative', margin: '0 10px', overflow: 'hidden' }}>
      {isSimulating && (
        <motion.div
          style={{ width: '30px', height: '4px', background: activeColor, borderRadius: '2px', position: 'absolute', top: 0 }}
          animate={{ left: ['-10%', '110%'] }}
          transition={{ repeat: Infinity, duration: 1.2, ease: 'linear', delay }}
        />
      )}
    </div>
  );

  const Node = ({ icon: Icon, title, subtitle, color, isPulse, customSvg, isCenter }) => (
    <div style={{ zIndex: 10, textAlign: 'center', flexShrink: 0, width: '100px' }}>
      <motion.div
        animate={isPulse && isSimulating ? { scale: [1, 1.05, 1] } : {}}
        transition={{ repeat: Infinity, duration: 2, ease: 'easeInOut' }}
        style={{
          width: isCenter ? '72px' : '56px',
          height: isCenter ? '72px' : '56px',
          borderRadius: isPulse ? '50%' : '12px',
          background: isCenter ? `${color}15` : 'var(--surface-elevated)',
          border: `2px solid ${color}`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: isSimulating ? `0 0 15px ${color}40` : 'none',
          margin: '0 auto'
        }}
      >
        {customSvg ? customSvg : <Icon size={isCenter ? 32 : 24} color={color} />}
      </motion.div>
      <div style={{ marginTop: '8px', fontSize: '11px', fontWeight: 'bold', color: 'var(--text-primary)', whiteSpace: 'nowrap' }}>
        {title}
      </div>
      <div style={{ fontSize: '10px', color: 'var(--text-muted)', whiteSpace: 'nowrap', marginTop: '2px' }}>
        {subtitle}
      </div>
    </div>
  );

  return (
    <div style={{
      width: '100%',
      padding: '30px 20px',
      background: 'var(--surface-card)',
      borderRadius: 'var(--radius-lg)',
      border: '1px solid var(--border-subtle)',
      position: 'relative',
      marginBottom: 'var(--space-6)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
    }}>

      <Node
        icon={Network}
        title="CAPTURE"
        subtitle={sourceLabel}
        color="var(--text-secondary)"
      />

      <Connector delay={0} baseColor="var(--accent-soft)" activeColor="var(--accent-primary)" />

      <Node
        title="MONI PROCESSING"
        subtitle="Flows & Features"
        color="var(--accent-primary)"
        isPulse={true}
        isCenter={true}
        customSvg={
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--accent-primary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
            <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
            <line x1="12" y1="22.08" x2="12" y2="12"></line>
          </svg>
        }
      />

      <Connector delay={0.4} baseColor="var(--accent-soft)" activeColor="var(--accent-secondary)" />

      <Node
        icon={ShieldAlert}
        title="DETECTION"
        subtitle="Rules & ML"
        color="var(--accent-secondary)"
        isPulse={true}
      />

      <Connector delay={0.8} baseColor="var(--accent-soft)" activeColor="var(--brand-magenta)" />

      <Node
        icon={Database}
        title="ALERTS / METRICS"
        subtitle="PostgreSQL"
        color="var(--brand-magenta)"
      />

    </div>
  );
}
