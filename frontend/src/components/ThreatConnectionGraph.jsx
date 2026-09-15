import React, { useMemo } from 'react';
import { motion } from 'framer-motion';
import { DETECTORS_CONFIG } from '../config';

export function ThreatConnectionGraph({ alerts }) {
  const data = useMemo(() => {
    const sources = [...new Set(alerts.map(a => a.source_ip).filter(Boolean))];
    const attacks = [...new Set(alerts.map(a => a.attack_type).filter(Boolean))];

    const sourceNodes = sources.map((ip, index) => ({
      id: ip,
      label: ip,
      type: 'source',
      y: (index + 1) * (300 / (sources.length + 1)),
    }));

    const attackNodes = attacks.map((type, index) => {
      const config = DETECTORS_CONFIG.find(c => c.type === type);
      return {
        id: type,
        label: config?.label || type,
        color: config?.color || '#8b5cf6',
        type: 'attack',
        y: (index + 1) * (300 / (attacks.length + 1)),
      };
    });

    const links = alerts.map(alert => {
      const sourceNode = sourceNodes.find(n => n.id === alert.source_ip);
      const attackNode = attackNodes.find(n => n.id === alert.attack_type);
      return {
        source: sourceNode,
        target: attackNode,
        color: attackNode?.color || '#8b5cf6',
        confidence: alert.confidence || 0.5,
      };
    }).filter(link => link.source && link.target);

    return { sourceNodes, attackNodes, links };
  }, [alerts]);

  if (alerts.length === 0) {
    return (
      <div style={{ height: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
        Awaiting threat data for relationship mapping.
      </div>
    );
  }

  return (
    <div style={{ width: '100%', height: '350px', position: 'relative', background: 'var(--surface-card)', borderRadius: 'var(--radius-lg)', padding: '24px', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}>
      <svg width="100%" height="100%" style={{ overflow: 'visible' }}>
        {data.links.map((link, i) => {
          const startX = '20%';
          const startY = link.source.y;
          const endX = '80%';
          const endY = link.target.y;
          const path = `M 20% ${startY} C 50% ${startY}, 50% ${endY}, 80% ${endY}`;
          
          return (
            <motion.path
              key={`link-${i}`}
              d={path}
              fill="none"
              stroke={link.color}
              strokeWidth={Math.max(1, link.confidence * 4)}
              strokeOpacity={0.3}
              initial={{ pathLength: 0, opacity: 0 }}
              animate={{ pathLength: 1, opacity: 1 }}
              transition={{ duration: 1.5, delay: i * 0.1, ease: 'easeInOut' }}
            />
          );
        })}

        {/* Source Nodes */}
        {data.sourceNodes.map((node, i) => (
          <g key={`source-${i}`} transform={`translate(20%, ${node.y})`}>
            <circle r={6} fill="var(--surface-elevated)" stroke="var(--text-muted)" strokeWidth={2} />
            <text x={-15} y={4} textAnchor="end" fill="var(--text-primary)" fontSize={12} fontWeight={600}>
              {node.label}
            </text>
          </g>
        ))}

        {/* Attack Nodes */}
        {data.attackNodes.map((node, i) => (
          <g key={`attack-${i}`} transform={`translate(80%, ${node.y})`}>
            <circle r={8} fill="var(--surface-elevated)" stroke={node.color} strokeWidth={3} />
            <text x={15} y={4} textAnchor="start" fill="var(--text-primary)" fontSize={13} fontWeight={700}>
              {node.label}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}
