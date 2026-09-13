const API_BASE = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

function getUrl(path) {
  if (API_BASE) {
    if (API_BASE.endsWith('/api') && path.startsWith('/api')) {
      return `${API_BASE}${path.substring(4)}`;
    }
    return `${API_BASE}${path}`;
  }
  return path;
}

export async function fetchStats() {
  const r = await fetch(getUrl('/api/stats'));
  return r.json();
}

export async function fetchAlerts() {
  const r = await fetch(getUrl('/api/alerts'));
  return r.json();
}

export async function fetchRankedAlerts() {
  const r = await fetch(getUrl('/api/alerts/ranked'));
  return r.json();
}

export async function fetchLiveNetwork() {
  const r = await fetch(getUrl('/api/network/live'));
  return r.json();
}

export async function fetchMode() {
  const r = await fetch(getUrl('/api/mode'));
  return r.json();
}

export async function toggleMode() {
  const r = await fetch(getUrl('/api/mode/toggle'), { method: 'POST' });
  return r.json();
}

export async function triggerDemoAttack(attackType) {
  const r = await fetch(getUrl('/api/demo/trigger'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attack_type: attackType }),
  });
  return r.json();
}

export async function analyzeLogin(payload) {
  const r = await fetch(getUrl('/api/login/analyze'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return r.json();
}

export async function seedDemoData() {
  const r = await fetch(getUrl('/api/demo/seed'), { method: 'POST' });
  return r.json();
}

export async function resetSystem() {
  const r = await fetch(getUrl('/api/reset'), { method: 'POST' });
  return r.json();
}
