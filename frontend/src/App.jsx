import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import ChartsSection from './components/ChartsSection';
import NetworkFeed from './components/NetworkFeed';
import AlertList from './components/AlertList';
import LoginTriageModal from './components/LoginTriageModal';
import {
  fetchStats,
  fetchAlerts,
  fetchLiveNetwork,
  fetchMode,
  toggleMode,
  triggerDemoAttack,
  seedDemoData,
} from './api';
import './App.css';

export default function App() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [networkEvents, setNetworkEvents] = useState([]);
  const [demoMode, setDemoMode] = useState(false);
  const [apiOnline, setApiOnline] = useState(false);
  const [toasts, setToasts] = useState([]);
  const [highlightNetwork, setHighlightNetwork] = useState(false);
  const [triageModalOpen, setTriageModalOpen] = useState(false);

  const addToast = (message, type = 'success') => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  };

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

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 3000);
    return () => clearInterval(interval);
  }, [refreshData]);

  const handleToggleMode = async () => {
    try {
      const res = await toggleMode();
      if (res.success) {
        setDemoMode(res.demo_mode);
        addToast(`Switched Watch Guard to ${res.label}`, 'success');
        refreshData();
      }
    } catch (err) {
      addToast('Failed to toggle system mode.', 'error');
    }
  };

  const handleTriggerAttack = async (attackType) => {
    try {
      const res = await triggerDemoAttack(attackType);
      if (res.success) {
        addToast(`⚡ Watch Guard detected synthetic ${attackType} vector!`, 'success');
        setHighlightNetwork(true);
        setTimeout(() => setHighlightNetwork(false), 1500);
        refreshData();
      }
    } catch (err) {
      addToast('Failed to trigger attack vector.', 'error');
    }
  };

  const handleSeedDemoData = async () => {
    try {
      addToast('⌛ Seeding 50,000+ Watch Guard telemetry events...', 'info');
      const res = await seedDemoData();
      if (res.success) {
        addToast(`✅ Seeded ${res.packets_seeded.toLocaleString()} packets & ${res.alerts_seeded} alerts!`, 'success');
        refreshData();
      }
    } catch (err) {
      addToast('Failed to seed demo data.', 'error');
    }
  };

  return (
    <div className="watch-guard-root">
      <Header
        demoMode={demoMode}
        onToggleMode={handleToggleMode}
        onTriggerAttack={handleTriggerAttack}
        apiOnline={apiOnline}
        onSeedDemoData={handleSeedDemoData}
        onOpenTriage={() => setTriageModalOpen(true)}
      />

      <main className="app-container">
        {/* Top Summary Metrics */}
        <Dashboard stats={stats} />

        {/* Dynamic Visualizations Grid */}
        <ChartsSection stats={stats} alerts={alerts} networkEvents={networkEvents} />

        {/* Live Feeds Grid */}
        <div className="grid-equal">
          <AlertList alerts={alerts} />
          <NetworkFeed events={networkEvents} highlighted={highlightNetwork} />
        </div>
      </main>

      {/* Interactive Login Triage Modal */}
      <LoginTriageModal
        isOpen={triageModalOpen}
        onClose={() => setTriageModalOpen(false)}
        onAlertGenerated={refreshData}
      />

      {/* Toast Notification Stack */}
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
