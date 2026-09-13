import React, { useState } from 'react';
import { Flame, Search, Filter } from 'lucide-react';

function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

export default function AlertList({ alerts }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const sorted = [...(alerts || [])].sort((a, b) => b.threat_score - a.threat_score);

  const filtered = sorted.filter((a) => {
    const matchesSev =
      filterSeverity === 'ALL' || (a.severity && a.severity.toUpperCase() === filterSeverity);
    const matchesQuery =
      !searchQuery ||
      (a.source_ip && a.source_ip.includes(searchQuery)) ||
      (a.alert_type && a.alert_type.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (a.description && a.description.toLowerCase().includes(searchQuery.toLowerCase()));

    return matchesSev && matchesQuery;
  });

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <Flame size={14} color="var(--high)" /> Security Incidents & Alerts
          <span className="count-badge">{filtered.length}</span>
        </div>

        {/* Filter and Search Bar */}
        <div className="feed-controls">
          <div className="search-input-wrapper">
            <Search size={12} className="search-icon" />
            <input
              type="text"
              placeholder="Search IP, alert type..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="search-input"
            />
          </div>

          <div className="filter-pills">
            <Filter size={11} className="filter-icon" />
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                className={`filter-btn ${filterSeverity === sev ? 'active' : ''} ${sev.toLowerCase()}`}
                onClick={() => setFilterSeverity(sev)}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="feed feed-ranked">
        {filtered.length === 0 ? (
          <div className="empty-feed">
            No matching security alerts found.
          </div>
        ) : (
          filtered.map((a, idx) => {
            const sevClass = (a.severity || 'low').toLowerCase();
            return (
              <div key={idx} className={`feed-row ${sevClass}`}>
                <div className="feed-time">{fmtTime(a.ts)}</div>
                <div className={`feed-sev ${sevClass}`}>
                  {a.severity || 'LOW'} ({a.threat_score}/100)
                </div>
                <div className="feed-type">
                  {a.alert_type}
                </div>
                <div className="feed-desc">
                  {a.source_ip && <span className="ip-link">{a.source_ip}</span>}
                  {' — '}
                  <span>{a.description}</span>
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
