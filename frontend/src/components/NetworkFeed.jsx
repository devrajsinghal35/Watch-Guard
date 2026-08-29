import React from 'react';
import { Activity } from 'lucide-react';

// Epoch timestamp ko readable format me clean convert karne ka time formatter function
function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

// Live capturing packets metadata grid box panels generator function
export default function NetworkFeed({ events, highlighted }) {
  return (
    <div className={`panel ${highlighted ? 'panel-highlight' : ''}`}>
      <div className="panel-header">
        <div className="panel-title">
          <Activity size={14} /> Live Network Feed
        </div>
      </div>
      <div className="feed">
        {/* Agar streams history arrays blank hain toh placeholder view message show karenge */}
        {!events || events.length === 0 ? (
          <div style={{ color: 'var(--text-dim)', padding: '30px 0', textAlign: 'center' }}>
            No live packet metadata recorded yet. Click "⚡ LIVE MODE" or "● DEMO MODE" to stream traffic.
          </div>
        ) : (
          /* Recent 50 packets streams screen logs print query mapping loop run */
          events.slice(0, 50).map((e, idx) => (
            <div key={idx} className="feed-row low">
              <div className="feed-time">{fmtTime(e.ts)}</div>
              <div className="feed-sev low">{e.protocol || 'TCP'}</div>
              <div>
                <strong>{e.source_ip}:{e.source_port}</strong>
                {' → '}
                <strong>{e.destination_ip}:{e.destination_port}</strong>
                {' '}
                <span style={{ color: 'var(--text-dim)', fontSize: '11px' }}>
                  ({e.length || 60} bytes)
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
