import React from 'react';
import { Shield, ShieldAlert, Activity, Flame, Radio, Zap } from 'lucide-react';

export default function Dashboard({ stats }) {
  const threatLevels = stats?.threat_levels || {};
  const totalHighCrit = (threatLevels.HIGH || 0) + (threatLevels.CRITICAL || 0);

  const items = [
    {
      label: 'Total Telemetry Packets',
      val: stats?.total_events ? stats.total_events.toLocaleString() : '0',
      icon: Activity,
      color: '#38bdf8',
      sub: 'Monitored Events',
    },
    {
      label: 'Security Alerts Triggered',
      val: stats?.total_alerts ? stats.total_alerts.toLocaleString() : '0',
      icon: Flame,
      color: '#f59e0b',
      sub: 'Rule Matches',
    },
    {
      label: 'Average Threat Score',
      val: stats?.avg_threat_score ? `${stats.avg_threat_score}/100` : '0/100',
      icon: Shield,
      color: stats?.avg_threat_score > 50 ? '#ef4444' : '#10b981',
      sub: 'Risk Baseline',
    },
    {
      label: 'Max Threat Severity',
      val: stats?.max_threat_score ? `${stats.max_threat_score}/100` : '0/100',
      icon: ShieldAlert,
      color: '#a855f7',
      sub: 'Peak Threat Intensity',
    },
    {
      label: 'High & Critical Incidents',
      val: totalHighCrit,
      icon: Zap,
      color: totalHighCrit > 0 ? '#ef4444' : '#64748b',
      sub: 'Immediate Triage Needed',
    },
    {
      label: 'Watch Guard Protection',
      val: 'ACTIVE',
      icon: Radio,
      color: '#10b981',
      sub: 'SOC Engine Online',
    },
  ];

  return (
    <section className="stat-grid">
      {items.map((it, idx) => {
        const IconComponent = it.icon;
        return (
          <div key={idx} className="stat-card">
            <div className="stat-card-top">
              <span className="stat-label">{it.label}</span>
              <div className="stat-icon-wrapper" style={{ color: it.color, background: `${it.color}15` }}>
                <IconComponent size={16} />
              </div>
            </div>
            <div className="stat-value">{it.val}</div>
            <div className="stat-sub">{it.sub}</div>
          </div>
        );
      })}
    </section>
  );
}
