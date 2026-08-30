import React from 'react';
import { Flame } from 'lucide-react';

// Formats epoch timestamps to a readable local time format for alert entries
function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

// Renders the list of security alerts
export default function AlertList({ alerts }) {
  // Sort the alerts array in descending order based on the threat score
  const sorted = [...(alerts || [])].sort((a, b) => b.threat_score - a.threat_score);

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <Flame size={14} /> Security Alerts
        </div>
      </div>
      <div className="feed feed-ranked">
        {/* Render placeholder message if there are no alerts */}
        {sorted.length === 0 ? (
          <div style={{ color: 'var(--text-dim)', padding: '30px 0', textAlign: 'center' }}>
            No security alerts detected.
          </div>
        ) : (
          /* Map through and render each threat alert record */
          sorted.map((a, idx) => {
            const sevClass = (a.severity || 'low').toLowerCase();
            return (
              <div key={idx} className={`feed-row ${sevClass}`}>
                <div className="feed-time">{fmtTime(a.ts)}</div>
                <div className={`feed-sev ${sevClass}`}>
                  {a.severity || 'LOW'} ({a.threat_score}/100)
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
                  {a.alert_type}
                </div>
                <div>
                  {a.source_ip && (
                    <span className="ip-link">{a.source_ip}</span>
                  )}
                  {' — '}
                  {a.description}
                </div>
                <div>
                  <span className="badge-cold">{a.protocol || 'TCP'}</span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
