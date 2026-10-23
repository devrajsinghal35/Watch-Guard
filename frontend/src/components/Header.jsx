import React from 'react';
import { Shield, Zap, Wifi, WifiOff, RotateCcw } from 'lucide-react';

export default function Header({
  demoMode,
  onToggleMode,
  onResetSystem,
  apiOnline,
}) {
  return (
    <header className="header">
      <div className="brand-section">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={20} color="#38bdf8" />
          </div>
          <span className="brand-name">WATCH GUARD</span>
        </div>
        <span className="header-subtitle">
          Real-Time Threat Intelligence & Network Security Operations Console
        </span>
      </div>

      <div className="header-actions">
        <div className={`status-badge ${apiOnline ? 'online' : 'offline'}`}>
          {apiOnline ? <Wifi size={13} /> : <WifiOff size={13} />}
          <span>{apiOnline ? 'API ONLINE' : 'DISCONNECTED'}</span>
        </div>

        <button
          className="btn-capture btn-reset"
          onClick={onResetSystem}
          title="Reset telemetry capture state"
        >
          <RotateCcw size={14} />
          RESET CAPTURE
        </button>

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
