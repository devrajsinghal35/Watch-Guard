import React, { useState } from 'react';
import { Activity, Pause, Play, ArrowDownUp } from 'lucide-react';

function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

export default function NetworkFeed({ events, highlighted }) {
  const [selectedProto, setSelectedProto] = useState('ALL');
  const [isPaused, setIsPaused] = useState(false);

  const rawEvents = events || [];
  const filteredEvents = rawEvents.filter((e) => {
    if (selectedProto === 'ALL') return true;
    return (e.protocol || 'TCP').toUpperCase() === selectedProto;
  });

  const displayEvents = isPaused ? filteredEvents.slice(0, 50) : filteredEvents.slice(0, 50);

  return (
    <div className={`panel ${highlighted ? 'panel-highlight' : ''}`}>
      <div className="panel-header">
        <div className="panel-title">
          <Activity size={14} color="var(--low)" /> Live Packet Stream
          <span className="count-badge">{displayEvents.length}</span>
        </div>

        <div className="feed-controls">
          <button
            className={`btn-icon-text ${isPaused ? 'active-pause' : ''}`}
            onClick={() => setIsPaused(!isPaused)}
            title={isPaused ? 'Resume stream' : 'Pause stream'}
          >
            {isPaused ? <Play size={12} /> : <Pause size={12} />}
            <span>{isPaused ? 'PAUSED' : 'STREAMING'}</span>
          </button>

          <div className="filter-pills">
            <ArrowDownUp size={11} className="filter-icon" />
            {['ALL', 'TCP', 'UDP'].map((proto) => (
              <button
                key={proto}
                className={`filter-btn ${selectedProto === proto ? 'active' : ''}`}
                onClick={() => setSelectedProto(proto)}
              >
                {proto}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="feed">
        {displayEvents.length === 0 ? (
          <div className="empty-feed">
            No live packet metadata recorded yet. Click "⚡ LIVE MODE" or "● DEMO MODE" to stream traffic.
          </div>
        ) : (
          displayEvents.map((e, idx) => (
            <div key={idx} className="feed-row low">
              <div className="feed-time">{fmtTime(e.ts)}</div>
              <div className="feed-sev low">{e.protocol || 'TCP'}</div>
              <div className="network-packet-info">
                <span className="ip-host">{e.source_ip}:{e.source_port}</span>
                <span className="arrow-flow">→</span>
                <span className="ip-host">{e.destination_ip}:{e.destination_port}</span>
                <span className="packet-bytes">
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
