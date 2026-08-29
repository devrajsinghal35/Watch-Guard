import React from 'react';

// Yeh component total alerts and averages metrics grid boxes draw karta hai dashboard summary stats update karne ke liye
export default function Dashboard({ stats }) {
  // Stats items structure configurations mapping metrics keys
  const items = [
    { label: 'Total Events', val: stats?.total_events ?? '—' },
    { label: 'Total Alerts', val: stats?.total_alerts ?? '—' },
    { label: 'Avg Threat Score', val: stats?.avg_threat_score ? `${stats.avg_threat_score}/100` : '—' },
    { label: 'Max Threat Score', val: stats?.max_threat_score ? `${stats.max_threat_score}/100` : '—' },
    { label: 'High / Critical', val: (stats?.threat_levels?.HIGH || 0) + (stats?.threat_levels?.CRITICAL || 0) },
    { label: 'System Mode', val: 'SOC ACTIVE' },
  ];

  return (
    <section className="stat-grid">
      {/* Map loop run karke har category ke dashboard grids banate hain */}
      {items.map((it, idx) => (
        <div key={idx} className="stat-card">
          <div className="stat-label">{it.label}</div>
          <div className="stat-value">{it.val}</div>
        </div>
      ))}
    </section>
  );
}
