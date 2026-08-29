import React from 'react';
import { Zap, Play, Wifi, WifiOff } from 'lucide-react';

// Sentry header navigation panel jo status details manage karta hai
export default function Header({ demoMode, onToggleMode, onTriggerAttack, apiOnline }) {
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

        {/* Demo mode options show hote hain agar state active ho */}
        {demoMode && (
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className="btn-demo-trigger"
              onClick={() => onTriggerAttack('PORT_SCAN')}
            >
              <Play size={12} /> Port Scan
            </button>
            <button
              className="btn-demo-trigger"
              onClick={() => onTriggerAttack('SYN_FLOOD')}
            >
              <Play size={12} /> SYN Flood
            </button>
            <button
              className="btn-demo-trigger"
              onClick={() => onTriggerAttack('BRUTE_FORCE')}
            >
              <Play size={12} /> Brute Force
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
