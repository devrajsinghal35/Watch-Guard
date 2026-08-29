// Yeh function stats data load karta hai Flask server se
export async function fetchStats() {
  const r = await fetch('/api/stats');
  return r.json();
}

// Yeh function security alerts fetch karta hai backend db se
export async function fetchAlerts() {
  const r = await fetch('/api/alerts');
  return r.json();
}

// Yeh function maximum threat scores ke according sorted alerts list fetch karta hai
export async function fetchRankedAlerts() {
  const r = await fetch('/api/alerts/ranked');
  return r.json();
}

// Yeh function live capture packets metadata return karta hai
export async function fetchLiveNetwork() {
  const r = await fetch('/api/network/live');
  return r.json();
}

// Yeh function system mode (Live vs Demo) check karta hai
export async function fetchMode() {
  const r = await fetch('/api/mode');
  return r.json();
}

// Yeh function toggle request bhejta hai sniffer start/stop karne ke liye
export async function toggleMode() {
  const r = await fetch('/api/mode/toggle', { method: 'POST' });
  return r.json();
}

// Yeh function demo endpoints trigger karta hai fake attacks inject karne ke liye
export async function triggerDemoAttack(attackType) {
  const r = await fetch('/api/demo/trigger', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attack_type: attackType }),
  });
  return r.json();
}

// Yeh function rule analysis form data submit karta hai login patterns check karne ke liye
export async function analyzeLogin(payload) {
  const r = await fetch('/api/login/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return r.json();
}
