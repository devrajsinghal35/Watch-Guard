import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import NetworkFeed from './components/NetworkFeed';
import AlertList from './components/AlertList';
import {
  fetchStats,
  fetchAlerts,
  fetchLiveNetwork,
  fetchMode,
  toggleMode,
  triggerDemoAttack,
} from './api';
import './App.css';

// Main App component jo complete dashboard state manage karta hai
export default function App() {
  // Application hooks state declarations
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [networkEvents, setNetworkEvents] = useState([]);
  const [demoMode, setDemoMode] = useState(false);
  const [apiOnline, setApiOnline] = useState(false);
  const [toasts, setToasts] = useState([]);
  const [highlightNetwork, setHighlightNetwork] = useState(false);

  // Screen alerts and success notifications update helper
  const addToast = (message, type = 'success') => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  };

  // Flask backend se data retrieve aur refresh karne wala main function
  const refreshData = useCallback(async () => {
    try {
      const [sRes, aRes, nRes, mRes] = await Promise.all([
        fetchStats(),
        fetchAlerts(),
        fetchLiveNetwork(),
        fetchMode(),
      ]);

      if (sRes.success) setStats(sRes.data);
      if (aRes.success) setAlerts(aRes.data || []);
      if (nRes.success) setNetworkEvents(nRes.data || []);
      if (mRes.success) setDemoMode(mRes.demo_mode);

      setApiOnline(true);
    } catch (err) {
      setApiOnline(false);
    }
  }, []);

  // Polling mechanism set karne ke liye hook (har 3 seconds me refresh)
  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 3000);
    return () => clearInterval(interval);
  }, [refreshData]);

  // Capture mode toggle callback function
  const handleToggleMode = async () => {
    try {
      const res = await toggleMode();
      if (res.success) {
        setDemoMode(res.demo_mode);
        addToast(`Switched to ${res.label}`, 'success');
        refreshData();
      }
    } catch (err) {
      addToast('Failed to toggle mode.', 'error');
    }
  };

  // Click attack tests button callback handler
  const handleTriggerAttack = async (attackType) => {
    try {
      const res = await triggerDemoAttack(attackType);
      if (res.success) {
        addToast(`⚡ Triggered synthetic ${attackType} attack test!`, 'success');
        setHighlightNetwork(true);
        setTimeout(() => setHighlightNetwork(false), 1500);
        refreshData();
      }
    } catch (err) {
      addToast('Failed to trigger demo attack.', 'error');
    }
  };

  return (
    <div>
      <Header
        demoMode={demoMode}
        onToggleMode={handleToggleMode}
        onTriggerAttack={handleTriggerAttack}
        apiOnline={apiOnline}
      />

      <main className="app-container">
        <Dashboard stats={stats} />
        
        <div className="grid-equal">
          <AlertList alerts={alerts} />
          <NetworkFeed events={networkEvents} highlighted={highlightNetwork} />
        </div>
      </main>

      <div className="toast-container">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.type}`}>
            <span>{t.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
