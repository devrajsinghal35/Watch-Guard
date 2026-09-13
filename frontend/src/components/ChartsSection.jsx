import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import { PieChart, TrendingUp, ShieldAlert, Activity } from 'lucide-react';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

export default function ChartsSection({ stats, alerts, networkEvents }) {
  // 1. Severity Distribution Data
  const threatLevels = stats?.threat_levels || { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  const doughnutData = {
    labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical'],
    datasets: [
      {
        data: [
          threatLevels.LOW || 0,
          threatLevels.MEDIUM || 0,
          threatLevels.HIGH || 0,
          threatLevels.CRITICAL || 0,
        ],
        backgroundColor: [
          'rgba(56, 189, 248, 0.85)',   // Low: Blue
          'rgba(245, 158, 11, 0.85)',   // Medium: Amber
          'rgba(239, 68, 68, 0.85)',    // High: Red
          'rgba(168, 85, 247, 0.85)',   // Critical: Purple
        ],
        borderColor: '#0d1217',
        borderWidth: 3,
        hoverOffset: 6,
      },
    ],
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: '#94a3b8',
          font: { family: 'IBM Plex Mono', size: 11 },
          padding: 12,
          usePointStyle: true,
        },
      },
      tooltip: {
        backgroundColor: '#0f172a',
        titleColor: '#f8fafc',
        bodyColor: '#cbd5e1',
        borderColor: '#1e293b',
        borderWidth: 1,
      },
    },
    cutout: '70%',
  };

  // 2. Timeline / Event Trend Chart (Aggregating events by 10s intervals or recent sequence)
  const recentEvents = [...(networkEvents || [])].slice(0, 20).reverse();
  const timelineLabels = recentEvents.map((e, i) => {
    if (!e.ts) return `#${i + 1}`;
    const date = new Date(e.ts * 1000);
    return date.toLocaleTimeString([], { hour12: false, minute: '2-digit', second: '2-digit' });
  });

  const timelineLengths = recentEvents.map((e) => e.length || 60);

  const lineData = {
    labels: timelineLabels.length > 0 ? timelineLabels : ['00:00', '00:05', '00:10', '00:15', '00:20'],
    datasets: [
      {
        fill: true,
        label: 'Packet Size (Bytes)',
        data: timelineLengths.length > 0 ? timelineLengths : [64, 128, 512, 256, 1024],
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56, 189, 248, 0.12)',
        tension: 0.35,
        pointBackgroundColor: '#38bdf8',
        pointRadius: 3,
      },
    ],
  };

  const lineOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        backgroundColor: '#0f172a',
        titleColor: '#f8fafc',
        bodyColor: '#cbd5e1',
        borderColor: '#1e293b',
        borderWidth: 1,
      },
    },
    scales: {
      x: {
        ticks: { color: '#64748b', font: { family: 'IBM Plex Mono', size: 10 } },
        grid: { color: 'rgba(255, 255, 255, 0.03)' },
      },
      y: {
        ticks: { color: '#64748b', font: { family: 'IBM Plex Mono', size: 10 } },
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
      },
    },
  };

  // 3. Top Attacker / Source IPs Chart
  const ipCounts = {};
  (alerts || []).forEach((a) => {
    if (a.source_ip) {
      ipCounts[a.source_ip] = (ipCounts[a.source_ip] || 0) + 1;
    }
  });

  const sortedIPs = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const barLabels = sortedIPs.length > 0 ? sortedIPs.map(([ip]) => ip) : ['192.168.1.188', '192.168.1.105', '192.168.1.201'];
  const barValues = sortedIPs.length > 0 ? sortedIPs.map(([, cnt]) => cnt) : [5, 3, 2];

  const barData = {
    labels: barLabels,
    datasets: [
      {
        label: 'Alert Count',
        data: barValues,
        backgroundColor: 'rgba(239, 68, 68, 0.75)',
        borderColor: '#ef4444',
        borderWidth: 1,
        borderRadius: 4,
      },
    ],
  };

  const barOptions = {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#0f172a',
        titleColor: '#f8fafc',
        bodyColor: '#cbd5e1',
        borderColor: '#1e293b',
        borderWidth: 1,
      },
    },
    scales: {
      x: {
        ticks: { color: '#64748b', font: { family: 'IBM Plex Mono', size: 10 } },
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
      },
      y: {
        ticks: { color: '#e2e8f0', font: { family: 'IBM Plex Mono', size: 10 } },
        grid: { display: false },
      },
    },
  };

  return (
    <div className="charts-grid">
      {/* Donut Chart: Threat Distribution */}
      <div className="panel chart-panel">
        <div className="panel-header">
          <div className="panel-title">
            <PieChart size={14} /> Threat Severity Matrix
          </div>
          <span className="chart-tag">Real-Time Distribution</span>
        </div>
        <div className="chart-wrapper">
          <Doughnut data={doughnutData} options={doughnutOptions} />
        </div>
      </div>

      {/* Line Chart: Traffic Throughput / Packet Size */}
      <div className="panel chart-panel">
        <div className="panel-header">
          <div className="panel-title">
            <TrendingUp size={14} /> Live Telemetry Throughput
          </div>
          <span className="chart-tag">Payload Analysis</span>
        </div>
        <div className="chart-wrapper">
          <Line data={lineData} options={lineOptions} />
        </div>
      </div>

      {/* Horizontal Bar Chart: Top Attacker IPs */}
      <div className="panel chart-panel">
        <div className="panel-header">
          <div className="panel-title">
            <ShieldAlert size={14} /> Top Flagged Threat Sources
          </div>
          <span className="chart-tag">IP Intelligence</span>
        </div>
        <div className="chart-wrapper">
          <Bar data={barData} options={barOptions} />
        </div>
      </div>
    </div>
  );
}
