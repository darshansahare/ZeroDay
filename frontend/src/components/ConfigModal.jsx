import React, { useState, useEffect } from 'react';
import { X, Key, ExternalLink, ShieldCheck, LogOut } from 'lucide-react';
import { authHeaders } from '../utils/csrf';

export default function ConfigModal({ isOpen, onClose, runtimeConfig, onConfigUpdated }) {
  const [adminKey, setAdminKey] = useState('');
  const [nebiusKey, setNebiusKey] = useState('');
  const [tavilyKey, setTavilyKey] = useState('');
  const [statusMsg, setStatusMsg] = useState('');
  const [isSuccess, setIsSuccess] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Close on Escape key
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Check auth status & reset form inputs when modal opens
  useEffect(() => {
    if (isOpen) {
      setAdminKey('');
      setNebiusKey('');
      setTavilyKey('');
      setStatusMsg('');
      setIsSuccess(false);

      // Probe auth status without leaking credentials
      fetch('/api/auth/status', { credentials: 'same-origin' })
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (data && data.authenticated) {
            setIsAuthenticated(true);
          } else {
            setIsAuthenticated(false);
          }
        })
        .catch(() => setIsAuthenticated(false));
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: authHeaders(),
        credentials: 'same-origin',
      });
      setIsAuthenticated(false);
      setAdminKey('');
      setStatusMsg('Logged out of admin session.');
      setIsSuccess(true);
    } catch {
      setStatusMsg('Failed to log out.');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setStatusMsg('Authenticating and applying runtime credentials server-side...');
    setIsSuccess(false);

    try {
      // 1. If user supplied an Admin Key, authenticate via POST /api/auth/login first
      if (adminKey.trim()) {
        const loginRes = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ api_key: adminKey.trim() }),
        });

        if (!loginRes.ok) {
          const err = await loginRes.json().catch(() => ({}));
          throw new Error(err.detail || 'Invalid administrative access key.');
        }

        setIsAuthenticated(true);
      }

      // 2. If provider keys are being updated, send POST /api/config
      const hasProviderKeys = Boolean(nebiusKey.trim() || tavilyKey.trim());
      if (hasProviderKeys) {
        const res = await fetch('/api/config', {
          method: 'POST',
          headers: authHeaders({ 'Content-Type': 'application/json' }),
          credentials: 'same-origin',
          body: JSON.stringify({
            nebius_api_key: nebiusKey.trim() || undefined,
            tavily_api_key: tavilyKey.trim() || undefined,
            llm_provider: 'nebius',
            search_provider: 'tavily',
          }),
        });

        if (res.ok) {
          const data = await res.json();
          setIsSuccess(true);
          setStatusMsg('Credentials successfully updated in server process memory.');
          if (onConfigUpdated) onConfigUpdated(data);
          setTimeout(() => {
            onClose();
          }, 900);
        } else {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.detail || 'Error updating configuration on server.');
        }
      } else if (adminKey.trim()) {
        // User logged in without updating provider keys
        setIsSuccess(true);
        setStatusMsg('Admin session verified and established.');
        setTimeout(() => {
          onClose();
        }, 900);
      }
    } catch (err) {
      setIsSuccess(false);
      setStatusMsg(err.message || 'Failed to connect to backend API server.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const isNebiusConfigured = Boolean(runtimeConfig?.nebius_configured);
  const isTavilyConfigured = Boolean(runtimeConfig?.tavily_configured);

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div className="modal-card font-onest" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-row">
            <Key className="modal-icon" size={20} />
            <h3 id="modal-title" className="font-onest">Operator & API Settings</h3>
          </div>
          <button className="modal-close" onClick={onClose} aria-label="Close configuration modal">
            <X size={18} />
          </button>
        </div>

        <p className="modal-desc font-onest">
          Configure server administration and AI provider credentials. ZeroDay includes a public demo mode for judges using pre-approved sample repositories. Administrator authorization is only required to modify server settings, update provider keys, or analyze custom external repositories.
        </p>

        <form onSubmit={handleSubmit} className="modal-form font-onest">
          {/* Administrative Server Authorization */}
          <div className="form-group" style={{ paddingBottom: '12px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <label
                htmlFor="modal-admin-key"
                className="font-onest modal-label-offwhite"
                style={{ fontFamily: "'Onest', sans-serif", fontSize: '12px', letterSpacing: '0.04em' }}
              >
                ADMIN ACCESS KEY (SERVER AUTHORIZATION)
              </label>
              {isAuthenticated ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '11px', color: '#10b981', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <ShieldCheck size={13} /> Active Session
                  </span>
                  <button
                    type="button"
                    onClick={handleLogout}
                    style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '11px', textDecoration: 'underline', padding: 0 }}
                    title="Log out of admin session"
                  >
                    Log out
                  </button>
                </div>
              ) : (
                <span style={{ fontSize: '11px', color: '#f59e0b' }}>
                  ● Operator login required for server configuration
                </span>
              )}
            </div>
            <input
              id="modal-admin-key"
              type="password"
              className="form-input font-mono"
              placeholder={isAuthenticated ? "Session active (enter key to renew or re-authenticate)" : "Enter ADMIN_API_KEY (optional for public demo)"}
              value={adminKey}
              onChange={(e) => setAdminKey(e.target.value)}
              autoComplete="off"
              spellCheck="false"
            />
            <div style={{ fontSize: '11px', color: '#8892b0', marginTop: '4px' }}>
              Optional for judges. Required only for server operators modifying API keys or executing custom external repositories.
            </div>
          </div>

          {/* Nebius Token Factory Key (NVIDIA Nemotron) */}
          <div className="form-group">
            <label
              htmlFor="modal-nebius-key"
              className="font-onest modal-label-offwhite"
              style={{ fontFamily: "'Onest', sans-serif", fontSize: '12px', letterSpacing: '0.04em' }}
            >
              NEBIUS TOKEN FACTORY API KEY (NVIDIA NEMOTRON)
            </label>
            <input
              id="modal-nebius-key"
              type="password"
              className="form-input font-mono"
              placeholder={isNebiusConfigured ? "Enter new key to replace configured key" : "Paste NEBIUS_API_KEY"}
              value={nebiusKey}
              onChange={(e) => setNebiusKey(e.target.value)}
              autoComplete="off"
              spellCheck="false"
            />
            <a
              href="https://tokenfactory.nebius.com"
              target="_blank"
              rel="noopener noreferrer"
              className="modal-key-link font-onest"
              style={{ fontFamily: "'Onest', sans-serif" }}
            >
              <span>Get API key from Nebius Token Factory</span>
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </div>

          {/* Tavily Threat Intel Key */}
          <div className="form-group">
            <label
              htmlFor="modal-tavily-key"
              className="font-onest modal-label-offwhite"
              style={{ fontFamily: "'Onest', sans-serif", fontSize: '12px', letterSpacing: '0.04em' }}
            >
              TAVILY THREAT INTEL API KEY
            </label>
            <input
              id="modal-tavily-key"
              type="password"
              className="form-input font-mono"
              placeholder={isTavilyConfigured ? "Enter new key to replace configured key" : "Paste TAVILY_API_KEY"}
              value={tavilyKey}
              onChange={(e) => setTavilyKey(e.target.value)}
              autoComplete="off"
              spellCheck="false"
            />
            <a
              href="https://tavily.com"
              target="_blank"
              rel="noopener noreferrer"
              className="modal-key-link font-onest"
              style={{ fontFamily: "'Onest', sans-serif" }}
            >
              <span>Get API key from Tavily</span>
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </div>

          {statusMsg && (
            <div className={`modal-status-banner ${isSuccess ? 'banner-success' : 'banner-info'}`} role="status">
              <span>{statusMsg}</span>
            </div>
          )}

          <div className="modal-actions">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="btn-modal-cancel font-onest"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || (!nebiusKey.trim() && !tavilyKey.trim() && !adminKey.trim())}
              className="btn-modal-save font-onest"
              id="btn-save-keys"
            >
              {isSubmitting ? 'Saving...' : 'Save Configuration'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
