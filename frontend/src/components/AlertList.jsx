import React from 'react';
import { Flame } from 'lucide-react';

// Epoch timestamp helper function for alerts time formats
function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

// Alerts lists container generator function
export default function AlertList({ alerts }) {
  // Alerts list array ko sorting algorithm run karke risk score ke high sequence variables sort order key map
  const sorted = [...(alerts || [])].sort((a, b) => b.threat_score - a.threat_score);

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <Flame size={14} /> Security Alerts
        </div>
      </div>
      <div className="feed feed-ranked">
        {/* Placeholder alert details verification agar empty data lists active state elements loop */}
        {sorted.length === 0 ? (
          <div style={{ color: 'var(--text-dim)', padding: '30px 0', textAlign: 'center' }}>
            No security alerts detected.
          </div>
        ) : (
          /* Har single threat alert item block card create query updates layout details */
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
