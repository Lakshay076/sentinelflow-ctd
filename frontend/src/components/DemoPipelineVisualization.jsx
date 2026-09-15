import React from 'react';
import { motion } from 'framer-motion';

export function DemoPipelineVisualization({ isRunning, currentVector }) {
  const isSimulating = Boolean(isRunning || currentVector);

  return (
    <div style={{
      width: '100%',
      height: '180px',
      background: 'var(--surface-card)',
      borderRadius: 'var(--radius-lg)',
      border: '1px solid var(--border-subtle)',
      position: 'relative',
      overflow: 'hidden',
      marginBottom: 'var(--space-6)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 40px'
    }}>
      
      {/* Network Source Node */}
      <div style={{ zIndex: 10, textAlign: 'center' }}>
        <div style={{
          width: '60px', height: '60px', borderRadius: '12px',
          background: 'var(--surface-elevated)', border: '2px solid var(--border-focus)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: isSimulating ? '0 0 20px var(--brand-blue-alpha)' : 'none',
          transition: 'box-shadow 0.3s ease'
        }}>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--text-primary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
            <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
            <line x1="6" y1="6" x2="6.01" y2="6"></line>
            <line x1="6" y1="18" x2="6.01" y2="18"></line>
          </svg>
        </div>
        <div style={{ marginTop: '8px', fontSize: '12px', fontWeight: 'bold', color: 'var(--text-secondary)' }}>
          {currentVector === 'PCAP' ? 'PCAP Replay' : 'Network Source'}
        </div>
      </div>

      {/* Connection Line 1 */}
      <div style={{ flex: 1, height: '4px', background: 'var(--surface-elevated)', position: 'relative', margin: '0 15px' }}>
        {isSimulating && (
          <motion.div
            style={{ width: '40px', height: '4px', background: 'var(--brand-blue)', borderRadius: '2px', position: 'absolute', top: 0 }}
            animate={{ left: ['0%', '100%'] }}
            transition={{ repeat: Infinity, duration: 0.8, ease: 'linear' }}
          />
        )}
      </div>

      {/* Analysis Engine Node */}
      <div style={{ zIndex: 10, textAlign: 'center' }}>
        <motion.div 
          animate={isSimulating ? { scale: [1, 1.05, 1] } : {}}
          transition={{ repeat: Infinity, duration: 2, ease: 'easeInOut' }}
          style={{
            width: '80px', height: '80px', borderRadius: '50%',
            background: 'var(--surface-elevated)', border: '2px solid var(--brand-violet)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: isSimulating ? '0 0 30px var(--brand-violet-alpha)' : 'none'
          }}
        >
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--brand-violet)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
            <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
            <line x1="12" y1="22.08" x2="12" y2="12"></line>
          </svg>
        </motion.div>
        <div style={{ marginTop: '12px', fontSize: '13px', fontWeight: 'bold', color: 'var(--text-primary)' }}>
          MONI Engine
        </div>
        <div style={{ fontSize: '10px', color: 'var(--brand-violet)' }}>
          {currentVector ? currentVector.replace('_', ' ') : 'IDLE'}
        </div>
      </div>

      {/* Connection Line 2 */}
      <div style={{ flex: 1, height: '4px', background: 'var(--surface-elevated)', position: 'relative', margin: '0 15px' }}>
        {isSimulating && (
          <motion.div
            style={{ width: '40px', height: '4px', background: 'var(--brand-magenta)', borderRadius: '2px', position: 'absolute', top: 0 }}
            animate={{ left: ['0%', '100%'] }}
            transition={{ repeat: Infinity, duration: 0.8, ease: 'linear', delay: 0.4 }}
          />
        )}
      </div>

      {/* Alert Sink Node */}
      <div style={{ zIndex: 10, textAlign: 'center' }}>
        <div style={{
          width: '60px', height: '60px', borderRadius: '12px',
          background: 'var(--surface-elevated)', border: '2px solid var(--brand-magenta)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: isSimulating ? '0 0 20px var(--brand-magenta-alpha)' : 'none'
        }}>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--brand-magenta)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>
        </div>
        <div style={{ marginTop: '8px', fontSize: '12px', fontWeight: 'bold', color: 'var(--text-secondary)' }}>
          Detection Sink
        </div>
      </div>

    </div>
  );
}
