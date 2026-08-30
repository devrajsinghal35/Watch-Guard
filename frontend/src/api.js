// Fetch summary stats data from the Flask server
export async function fetchStats() {
  const r = await fetch('/api/stats');
  return r.json();
}

// Fetch security alerts from the backend database
export async function fetchAlerts() {
  const r = await fetch('/api/alerts');
  return r.json();
}

// Fetch ranked alerts sorted by threat score in descending order
export async function fetchRankedAlerts() {
  const r = await fetch('/api/alerts/ranked');
  return r.json();
}

// Fetch live captured network packet metadata
export async function fetchLiveNetwork() {
  const r = await fetch('/api/network/live');
  return r.json();
}

// Get the current system mode (Live vs Demo)
export async function fetchMode() {
  const r = await fetch('/api/mode');
  return r.json();
}

// Toggle the system mode and start/stop the background sniffer thread
export async function toggleMode() {
  const r = await fetch('/api/mode/toggle', { method: 'POST' });
  return r.json();
}

// Trigger simulated synthetic attacks in demo mode
export async function triggerDemoAttack(attackType) {
  const r = await fetch('/api/demo/trigger', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attack_type: attackType }),
  });
  return r.json();
}

// Submit login form payload to analyze the threat/risk level
export async function analyzeLogin(payload) {
  const r = await fetch('/api/login/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return r.json();
}

// Request the backend to instantly seed 50,000+ mock packets and alerts
export async function seedDemoData() {
  const r = await fetch('/api/demo/seed', { method: 'POST' });
  return r.json();
}
