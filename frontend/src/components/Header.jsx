import React from 'react';
import { Shield, Zap, Play, Wifi, WifiOff, Terminal } from 'lucide-react';

export default function Header({
  demoMode,
  onToggleMode,
  onTriggerAttack,
  apiOnline,
  onSeedDemoData,
  onOpenTriage,
}) {
  return (
    <header className="header">
      <div className="brand-section">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={20} color="#38bdf8" />
          </div>
          <span className="brand-name">WATCH GUARD</span>
          <span className="brand-badge">SOC 2.0</span>
        </div>
        <span className="header-subtitle">
          Real-Time Threat Intelligence & Network Security Operations Console
        </span>
      </div>

      <div className="header-actions">
        {/* Connection status indicator */}
        <div className={`status-badge ${apiOnline ? 'online' : 'offline'}`}>
          {apiOnline ? <Wifi size={13} /> : <WifiOff size={13} />}
          <span>{apiOnline ? 'API ONLINE' : 'DISCONNECTED'}</span>
        </div>

        {/* Live Sniffing / Demo Mode toggle button */}
        <button
          className={`btn-capture ${demoMode ? 'active' : ''}`}
          onClick={onToggleMode}
        >
          <Zap size={14} />
          {demoMode ? '● DEMO MODE' : '⚡ LIVE MODE'}
        </button>
      </div>
    </header>
  );
}
