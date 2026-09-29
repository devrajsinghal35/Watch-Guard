import React, { useState } from 'react';
import { Flame, Search, Filter, Bot, X } from 'lucide-react';
import { analyzeIncident } from '../api';

function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

export default function AlertList({ alerts }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [analyzingId, setAnalyzingId] = useState(null);
  const [playbookData, setPlaybookData] = useState({});

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

  const handleAnalyze = async (alert) => {
    const alertKey = alert.id || alert.ts || alert.description;
    setAnalyzingId(alertKey);
    try {
      const res = await analyzeIncident(alert);
      if (res.success) {
        setPlaybookData((prev) => ({ ...prev, [alertKey]: res.playbook }));
      }
    } catch (err) {
      console.error("AI Analysis failed:", err);
    }
    setAnalyzingId(null);
  };

  const closePlaybook = (alertKey) => {
    setPlaybookData((prev) => {
      const newData = { ...prev };
      delete newData[alertKey];
      return newData;
    });
  };

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
            const alertKey = a.id || a.ts || idx;
            const sevClass = (a.severity || 'low').toLowerCase();
            const isAnalyzing = analyzingId === alertKey;
            const playbook = playbookData[alertKey];

            return (
              <React.Fragment key={alertKey}>
                <div className={`feed-row ${sevClass}`}>
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
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <span className="badge-cold">{a.protocol || 'TCP'}</span>
                    <button 
                      className="ai-copilot-btn"
                      onClick={() => handleAnalyze(a)}
                      disabled={isAnalyzing}
                      style={{
                        background: 'linear-gradient(90deg, #6366f1, #a855f7)',
                        border: 'none',
                        borderRadius: '4px',
                        padding: '4px 8px',
                        color: 'white',
                        fontSize: '10px',
                        fontWeight: 'bold',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}
                    >
                      <Bot size={12} />
                      {isAnalyzing ? 'Analyzing...' : 'Ask AI'}
                    </button>
                  </div>
                </div>
                {playbook && (
                  <div className="ai-playbook-panel" style={{
                    margin: '4px 16px 12px 16px',
                    padding: '12px',
                    background: 'rgba(99, 102, 241, 0.1)',
                    borderLeft: '2px solid #a855f7',
                    borderRadius: '4px',
                    fontSize: '12px',
                    color: '#e2e8f0',
                    position: 'relative'
                  }}>
                    <button 
                      onClick={() => closePlaybook(alertKey)} 
                      style={{ position: 'absolute', top: '8px', right: '8px', background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
                    >
                      <X size={14} />
                    </button>
                    <div style={{ fontWeight: 'bold', color: '#a855f7', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Bot size={14} /> AI Copilot Analysis (Confidence: {playbook.confidence_score * 100}%)
                    </div>
                    <div style={{ marginBottom: '6px' }}><strong>Summary:</strong> {playbook.summary}</div>
                    <div style={{ marginBottom: '6px' }}><strong>Root Cause:</strong> {playbook.root_cause}</div>
                    <div style={{ marginBottom: '6px' }}><strong>Remediation Steps:</strong></div>
                    <ul style={{ margin: '0 0 8px 20px', padding: '0' }}>
                      {playbook.remediation_steps.map((step, sIdx) => <li key={sIdx}>{step}</li>)}
                    </ul>
                    {playbook.recommended_firewall_rule && (
                      <div>
                        <strong>Recommended Rule:</strong>
                        <code style={{ display: 'block', background: '#0f172a', padding: '6px', borderRadius: '4px', marginTop: '4px', color: '#4ade80' }}>
                          {playbook.recommended_firewall_rule}
                        </code>
                      </div>
                    )}
                  </div>
                )}
              </React.Fragment>
            );
          })
        )}
      </div>
    </div>
  );
}
