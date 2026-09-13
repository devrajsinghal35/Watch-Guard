import React, { useState } from 'react';
import { X, ShieldAlert, CheckCircle, AlertTriangle, Send } from 'lucide-react';
import { analyzeLogin } from '../api';

export default function LoginTriageModal({ isOpen, onClose, onAlertGenerated }) {
  const [formData, setFormData] = useState({
    source_ip: '45.33.32.156',
    username: 'admin',
    service: 'SSH',
    port: '22',
    status: 'failed',
    failed_attempts: '6',
  });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  if (!isOpen) return null;

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const res = await analyzeLogin({
        ...formData,
        port: parseInt(formData.port, 10),
        failed_attempts: parseInt(formData.failed_attempts, 10),
      });

      if (res.success) {
        setResult(res.result);
        if (onAlertGenerated) onAlertGenerated();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title">
            <ShieldAlert size={16} color="var(--accent)" />
            <span>Watch Guard — Authentication Threat Triage</span>
          </div>
          <button className="btn-icon" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="triage-form">
          <div className="form-grid-modal">
            <div className="form-group">
              <label>Source IP Address</label>
              <input
                type="text"
                name="source_ip"
                value={formData.source_ip}
                onChange={handleChange}
                placeholder="e.g. 192.168.1.50"
                required
              />
            </div>

            <div className="form-group">
              <label>Target Username</label>
              <input
                type="text"
                name="username"
                value={formData.username}
                onChange={handleChange}
                placeholder="e.g. root, admin"
                required
              />
            </div>

            <div className="form-group">
              <label>Protocol / Service</label>
              <select name="service" value={formData.service} onChange={handleChange}>
                <option value="SSH">SSH (Port 22)</option>
                <option value="FTP">FTP (Port 21)</option>
                <option value="RDP">RDP (Port 3389)</option>
                <option value="HTTP">HTTP Auth (Port 80/443)</option>
              </select>
            </div>

            <div className="form-group">
              <label>Destination Port</label>
              <input
                type="number"
                name="port"
                value={formData.port}
                onChange={handleChange}
                required
              />
            </div>

            <div className="form-group">
              <label>Attempt Status</label>
              <select name="status" value={formData.status} onChange={handleChange}>
                <option value="failed">FAILED</option>
                <option value="success">SUCCESS</option>
              </select>
            </div>

            <div className="form-group">
              <label>Consecutive Failures</label>
              <input
                type="number"
                name="failed_attempts"
                value={formData.failed_attempts}
                onChange={handleChange}
                min="1"
                required
              />
            </div>
          </div>

          <button type="submit" className="btn-triage-submit" disabled={loading}>
            <Send size={14} />
            {loading ? 'Evaluating Pattern...' : 'Simulate & Analyze Event'}
          </button>
        </form>

        {result && (
          <div className={`triage-result ${result.risk_level.toLowerCase()}`}>
            <div className="result-header">
              {result.risk_level === 'HIGH' ? (
                <AlertTriangle size={18} color="var(--high)" />
              ) : (
                <CheckCircle size={18} color="var(--ok)" />
              )}
              <span className="result-title">
                Risk Classification: <strong>{result.risk_level}</strong> ({result.threat_score}/100)
              </span>
            </div>
            <p className="result-reason">{result.reason}</p>
          </div>
        )}
      </div>
    </div>
  );
}
