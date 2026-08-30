import React from 'react';

// This component draws the metric summary cards for the SOC dashboard
export default function Dashboard({ stats }) {
  // Mapping metrics to display labels and values
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
      {/* Map through the items to render each metric card */}
      {items.map((it, idx) => (
        <div key={idx} className="stat-card">
          <div className="stat-label">{it.label}</div>
          <div className="stat-value">{it.val}</div>
        </div>
      ))}
    </section>
  );
}
