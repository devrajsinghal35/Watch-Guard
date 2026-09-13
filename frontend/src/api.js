const API_BASE = 'http://127.0.0.1:5050';

export async function fetchStats() {
  const r = await fetch(`${API_BASE}/api/stats`);
  return r.json();
}

export async function fetchAlerts() {
  const r = await fetch(`${API_BASE}/api/alerts`);
  return r.json();
}

export async function fetchRankedAlerts() {
  const r = await fetch(`${API_BASE}/api/alerts/ranked`);
  return r.json();
}

export async function fetchLiveNetwork() {
  const r = await fetch(`${API_BASE}/api/network/live`);
  return r.json();
}

export async function fetchMode() {
  const r = await fetch(`${API_BASE}/api/mode`);
  return r.json();
}

export async function toggleMode() {
  const r = await fetch(`${API_BASE}/api/mode/toggle`, { method: 'POST' });
  return r.json();
}

export async function triggerDemoAttack(attackType) {
  const r = await fetch(`${API_BASE}/api/demo/trigger`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attack_type: attackType }),
  });
  return r.json();
}

export async function analyzeLogin(payload) {
  const r = await fetch(`${API_BASE}/api/login/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return r.json();
}

export async function seedDemoData() {
  const r = await fetch(`${API_BASE}/api/demo/seed`, { method: 'POST' });
  return r.json();
}
