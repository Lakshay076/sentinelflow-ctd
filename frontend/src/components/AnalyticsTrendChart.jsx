import React, { useRef, useEffect } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import gsap from 'gsap';

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div style={{
        background: 'var(--surface-elevated)',
        border: '1px solid var(--border-focus)',
        padding: '12px',
        borderRadius: '8px',
        boxShadow: 'var(--shadow-glow-accent)',
        color: 'var(--text-primary)'
      }}>
        <div style={{ fontSize: '14px', fontWeight: '700', marginBottom: '4px' }}>
          {Number(data.value).toFixed(1)} pkt/s
        </div>
        <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
          Timestamp: {new Date(data.timestamp * 1000).toLocaleTimeString()}
        </div>
      </div>
    );
  }
  return null;
};

export function AnalyticsTrendChart({ points }) {
  const containerRef = useRef(null);
  
  useEffect(() => {
    // GSAP entrance animation for the chart container
    if (containerRef.current) {
      gsap.fromTo(
        containerRef.current,
        { opacity: 0, y: 20 },
        { opacity: 1, y: 0, duration: 1, ease: 'power3.out' }
      );
    }
  }, []);

  const chartData = points.map(p => ({
    timestamp: p.timestamp,
    value: Number(p.packets_per_second) || 0,
  }));

  if (chartData.length === 0) {
    return (
      <div style={{ height: '250px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
        Waiting for traffic telemetry...
      </div>
    );
  }

  return (
    <div ref={containerRef} style={{ width: '100%', height: 280, marginTop: 'var(--space-4)' }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={chartData}
          margin={{ top: 10, right: 0, left: -20, bottom: 0 }}
        >
          <defs>
            <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="var(--brand-magenta)" stopOpacity={0.8}/>
              <stop offset="95%" stopColor="var(--brand-magenta)" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border-subtle)" />
          <XAxis 
            dataKey="timestamp" 
            hide 
          />
          <YAxis 
            tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area 
            type="monotone" 
            dataKey="value" 
            stroke="var(--brand-magenta)" 
            strokeWidth={3}
            fillOpacity={1} 
            fill="url(#colorValue)" 
            animationDuration={2000}
            animationEasing="ease-in-out"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
