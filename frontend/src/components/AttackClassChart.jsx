import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { DETECTORS_CONFIG } from '../config';

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="chart-tooltip" style={{
        background: 'var(--surface-elevated)',
        border: '1px solid var(--border-subtle)',
        padding: 'var(--space-3)',
        borderRadius: 'var(--radius-md)',
        boxShadow: 'var(--shadow-lg)',
        color: 'var(--text-primary)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: data.color }} />
          <strong style={{ fontSize: '13px' }}>{data.label}</strong>
        </div>
        <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
          Incidents: <strong style={{ color: 'var(--text-primary)' }}>{data.count}</strong>
        </div>
        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
          {data.pct}% of total traffic
        </div>
      </div>
    );
  }
  return null;
};

export function AttackClassChart({ stats, historyLength }) {
  const chartData = DETECTORS_CONFIG.map((det) => {
    const count = stats?.attack_types?.[det.type] ?? 0;
    const pct = historyLength ? Math.round((count / historyLength) * 100) : 0;
    return {
      name: det.type,
      label: det.label,
      count,
      pct,
      color: det.color,
    };
  }).sort((a, b) => b.count - a.count); // Sort descending

  if (!historyLength) {
    return (
      <div style={{ height: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
        No threat data recorded yet.
      </div>
    );
  }

  return (
    <div style={{ width: '100%', height: 350, marginTop: 'var(--space-4)' }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={chartData}
          layout="vertical"
          margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="var(--border-subtle)" />
          <XAxis 
            type="number" 
            tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
            axisLine={{ stroke: 'var(--border-subtle)' }}
            tickLine={false}
          />
          <YAxis 
            dataKey="label" 
            type="category" 
            tick={{ fill: 'var(--text-secondary)', fontSize: 12, fontWeight: 500 }}
            axisLine={{ stroke: 'var(--border-subtle)' }}
            tickLine={false}
            width={140}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'var(--surface-hover)' }} />
          <Bar 
            dataKey="count" 
            radius={[0, 4, 4, 0]}
            barSize={24}
            animationDuration={1500}
            animationEasing="ease-out"
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
