import React, { useEffect, useRef } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Filler,
} from 'chart.js';
import { Line } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Filler
);

export function LiveTrafficChart({ points, maxPps }) {
  const chartRef = useRef(null);

  const now = Date.now();
  const data = {
    datasets: [
      {
        label: 'Packets / Sec',
        data: points.map(p => ({
          x: p.timestamp ? p.timestamp * 1000 : now,
          y: p.packets_per_second || 0
        })),
        borderColor: '#8b5cf6', // var(--brand-violet)
        borderWidth: 2,
        tension: 0.4,
        fill: true,
        backgroundColor: (context) => {
          const ctx = context.chart.ctx;
          const gradient = ctx.createLinearGradient(0, 0, 0, context.chart.height);
          gradient.addColorStop(0, 'rgba(139, 92, 246, 0.4)');
          gradient.addColorStop(1, 'rgba(139, 92, 246, 0.0)');
          return gradient;
        },
        pointRadius: 0,
        pointHoverRadius: 4,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
      duration: 0, 
    },
    scales: {
      x: {
        type: 'linear',
        display: false, // Hide X axis line and labels as they are drawn in HTML
        min: now - 60000,
        max: now,
      },
      y: {
        display: true,
        border: { display: false },
        grid: {
          color: 'rgba(148, 163, 184, 0.1)', 
        },
        ticks: {
          color: 'var(--text-muted)',
          maxTicksLimit: 5,
        },
        suggestedMax: maxPps * 1.2 || 10,
        beginAtZero: true,
      },
    },
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        mode: 'index',
        intersect: false,
        backgroundColor: 'rgba(15, 23, 42, 0.95)', 
        titleColor: '#ffffff',
        titleFont: { size: 13, weight: 'bold' },
        bodyColor: '#cbd5e1', 
        bodyFont: { size: 12 },
        borderColor: 'rgba(148, 163, 184, 0.2)',
        borderWidth: 1,
        padding: 10,
        displayColors: false,
        callbacks: {
          title: (tooltipItems) => {
            const timestampMs = tooltipItems[0].parsed.x;
            return timestampMs && !isNaN(timestampMs) 
              ? new Date(timestampMs).toLocaleTimeString() 
              : 'Live Observation';
          },
          label: (context) => `Packet Rate — ${context.parsed.y.toFixed(1)} pkt/s`
        }
      },
    },
    interaction: {
      mode: 'nearest',
      axis: 'x',
      intersect: false,
    },
  };

  return (
    <div style={{ width: '100%', height: '100%' }}>
      <Line ref={chartRef} data={data} options={options} />
    </div>
  );
}
