import React from 'react';
import { Zap, Play, Wifi, WifiOff } from 'lucide-react';

// Sentry header navigation panel displaying system status and controls
export default function Header({ demoMode, onToggleMode, onTriggerAttack, apiOnline, onSeedDemoData }) {
  return (
    <header className="header">
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <div className="brand">
          <span className="brand-dot"></span>
          SENTRY SOC
        </div>
        <span className="header-subtitle">
          Network Security Monitoring & SOC Alert Dashboard
        </span>
      </div>

      <div className="header-actions">
        {/* API connection status status indicators */}
        <div className={`status-badge ${apiOnline ? 'online' : 'offline'}`}>
          {apiOnline ? <Wifi size={14} /> : <WifiOff size={14} />}
          <span>{apiOnline ? 'API ONLINE' : 'DISCONNECTED'}</span>
        </div>

        {/* Live Sniffing start / stop buttons */}
        <button
          className={`btn-capture ${demoMode ? 'active' : ''}`}
          onClick={onToggleMode}
        >
          <Zap size={14} />
          {demoMode ? '● DEMO MODE' : '⚡ LIVE MODE'}
        </button>

        {/* In Demo Mode, show the Seed 50k Packets option */}
        {demoMode && (
          <button
            className="btn-capture"
            style={{ background: 'var(--accent)', color: '#ffffff' }}
            onClick={onSeedDemoData}
          >
            <Play size={14} /> Seed 50k Packets
          </button>
        )}
      </div>
    </header>
  );
}
