import React, { useState, useCallback, useEffect, useRef } from 'react';
import {
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { SAMPLE_REPOSITORIES } from '../config/sampleRepositories';
import { authHeaders } from '../utils/csrf';

function GithubIcon({ size = 16, className = "" }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"></path>
    </svg>
  );
}

export default function ArenaTargetSelect({
  onSelectRun,
  openConfigModal,
  systemHealth,
}) {
  // Input and selection state
  const [repoUrl, setRepoUrl] = useState('');
  const [selectedCardId, setSelectedCardId] = useState(null);
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState(null);
  const [validationError, setValidationError] = useState('');
  const [validationErrorShakeKey, setValidationErrorShakeKey] = useState(0);
  const validationErrorTimerRef = useRef(null);
  const [isStarting, setIsStarting] = useState(false);
  const [startError, setStartError] = useState('');
  const [showMissingKeyAlert, setShowMissingKeyAlert] = useState(false);
  const [alertShakeKey, setAlertShakeKey] = useState(0);
  const alertTimerRef = useRef(null);

  // Integration credentials check (Nebius Token Factory & Tavily)
  const hasLlm = Boolean(systemHealth?.nebius_configured);
  const hasSearch = Boolean(systemHealth?.tavily_configured);
  const keysMissing = !hasLlm || !hasSearch;



  // Trigger missing key alert and auto-dismiss after a few seconds (4s)
  const triggerMissingKeyAlert = useCallback(() => {
    setShowMissingKeyAlert(true);
    setAlertShakeKey((k) => k + 1);
    if (alertTimerRef.current) clearTimeout(alertTimerRef.current);
    alertTimerRef.current = setTimeout(() => {
      setShowMissingKeyAlert(false);
    }, 4000);
  }, []);

  // Trigger validation error and auto-dismiss after a few seconds (4s)
  const triggerValidationError = useCallback((msg = 'Invalid GitHub repository URL') => {
    setValidationError(msg);
    setValidationErrorShakeKey((k) => k + 1);
    if (validationErrorTimerRef.current) clearTimeout(validationErrorTimerRef.current);
    validationErrorTimerRef.current = setTimeout(() => {
      setValidationError('');
    }, 4000);
  }, []);

  // Cleanup timers on unmount
  useEffect(() => {
    return () => {
      if (alertTimerRef.current) clearTimeout(alertTimerRef.current);
      if (validationErrorTimerRef.current) clearTimeout(validationErrorTimerRef.current);
    };
  }, []);

  // Hide missing key alert when keys become configured
  useEffect(() => {
    if (!keysMissing) {
      setShowMissingKeyAlert(false);
      if (alertTimerRef.current) clearTimeout(alertTimerRef.current);
    }
  }, [keysMissing]);

  // Handle typing in the GitHub URL input
  const handleUrlInputChange = (e) => {
    const val = e.target.value;
    setRepoUrl(val);
    setSelectedCardId(null);
    setValidationResult(null);
    setValidationError('');
    if (validationErrorTimerRef.current) clearTimeout(validationErrorTimerRef.current);
    setStartError('');
  };

  // Validate GitHub repository via backend
  const validateRepoUrl = useCallback(async (urlToValidate) => {
    const url = (urlToValidate !== undefined ? urlToValidate : repoUrl).trim();
    if (!url) {
      triggerValidationError('Invalid GitHub repository URL');
      return null;
    }

    setIsValidating(true);
    setValidationError('');
    if (validationErrorTimerRef.current) clearTimeout(validationErrorTimerRef.current);
    setStartError('');

    try {
      const res = await fetch('/api/repos/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.valid) {
        triggerValidationError('Invalid GitHub repository URL');
        setValidationResult(null);
        return null;
      }

      setValidationResult(data);
      return data;
    } catch {
      triggerValidationError('Invalid GitHub repository URL');
      setValidationResult(null);
      return null;
    } finally {
      setIsValidating(false);
    }
  }, [repoUrl, triggerValidationError]);

  // Handle clicking one of the sample repository choices: starts analysis immediately without requiring a second click
  const handleSelectSampleChoice = async (sample) => {
    if (isStarting || isValidating) return;

    setSelectedCardId(sample.id);
    setRepoUrl('');
    setValidationError('');
    setStartError('');
    setIsStarting(true);

    try {
      const targetPayload = {
        target_path: sample.targetPath || 'app.py',
        repo_url: sample.url,
        commit_sha: 'HEAD',
        max_repair_attempts: 3,
        async_mode: true,
      };

      const res = await fetch('/api/runs', {
        method: 'POST',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        credentials: 'same-origin',
        body: JSON.stringify(targetPayload),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        if (res.status === 403) {
          throw new Error('Public demo mode is restricted to the pre-approved sample repositories below. Administrator access is required to run analysis on custom external repositories.');
        }
        if (res.status === 401) {
          throw new Error('Administrator authorization required for custom repository execution. Please enter your Admin Access Key in Settings.');
        }
        throw new Error(errData.detail || `Server returned HTTP ${res.status}`);
      }

      const runSummary = await res.json();
      if (!runSummary.run_id) {
        throw new Error('Backend response did not contain a valid run identifier.');
      }

      onSelectRun(runSummary.run_id, runSummary);
    } catch (err) {
      setStartError(err.message || 'Failed to start analysis.');
      setIsStarting(false);
    }
  };

  // Handle clicking the Start Analysis button or pressing Enter on custom URL
  const handleStartAnalysis = async () => {
    const trimmedUrl = repoUrl.trim();
    if (!trimmedUrl) {
      triggerValidationError('Invalid GitHub repository URL');
      return;
    }

    if (isStarting || isValidating) return;

    let validData = validationResult;
    if (!validData || validData.url !== trimmedUrl) {
      validData = await validateRepoUrl(trimmedUrl);
      if (!validData || !validData.valid) {
        return;
      }
    }

    setIsStarting(true);
    setStartError('');

    try {
      const targetPayload = {
        target_path: 'app.py',
        repo_url: validData.url,
        commit_sha: validData.commit_sha || validData.pinned_commit || 'HEAD',
        max_repair_attempts: 3,
        async_mode: true,
      };

      const res = await fetch('/api/runs', {
        method: 'POST',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        credentials: 'same-origin',
        body: JSON.stringify(targetPayload),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        if (res.status === 403) {
          throw new Error('Public demo mode is restricted to the pre-approved sample repositories below. Administrator access is required to run analysis on custom external repositories.');
        }
        if (res.status === 401) {
          throw new Error('Administrator authorization required for custom repository execution. Please enter your Admin Access Key in Settings.');
        }
        throw new Error(errData.detail || `Server returned HTTP ${res.status}`);
      }

      const runSummary = await res.json();
      if (!runSummary.run_id) {
        throw new Error('Backend response did not contain a valid run identifier.');
      }

      onSelectRun(runSummary.run_id, runSummary);
    } catch (err) {
      setStartError(err.message || 'Failed to start analysis.');
      setIsStarting(false);
    }
  };

  return (
    <div className="arena-launcher-page">
      <main className="arena-launcher-container">
        {/* Centered Launcher Header */}
        <section className="launcher-header">
          <h1 className="launcher-title font-oxanium">Let&apos;s find what breaks.</h1>
          <p className="launcher-description font-onest">
            Analyze a repository. Reproduce vulnerabilities. Verify the fix.
          </p>
        </section>

        {/* Launcher Main Card */}
        <div className="launcher-card">
          {/* Row 1: URL input on the left + Start Analysis button on the right */}
          <div className="launcher-action-row">
            <div className="url-input-wrapper">
              <GithubIcon size={16} className="url-input-icon" />
              <input
                id="github-repo-url-input"
                type="url"
                value={repoUrl}
                onChange={handleUrlInputChange}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleStartAnalysis();
                }}
                placeholder="https://github.com/owner/repository"
                className="launcher-url-input font-mono"
                disabled={isValidating || isStarting}
                aria-label="Public GitHub repository URL"
                autoComplete="off"
                spellCheck="false"
              />
            </div>

            {/* Start Analysis Button */}
            <button
              type="button"
              onClick={handleStartAnalysis}
              disabled={isValidating || isStarting}
              className="btn-start-analysis font-onest"
              id="btn-start-analysis"
            >
              {isValidating ? (
                <>
                  <Loader2 size={15} className="spin-icon" />
                  <span>Validating...</span>
                </>
              ) : isStarting ? (
                <>
                  <Loader2 size={15} className="spin-icon" />
                  <span>Starting...</span>
                </>
              ) : (
                <span>Start Analysis &rarr;</span>
              )}
            </button>
          </div>

          {/* Validation Feedback Callout if present */}
          {validationError && (
            <div
              key={validationErrorShakeKey}
              id="validation-error-alert"
              className="launcher-alert alert-error font-onest"
              role="alert"
            >
              <AlertCircle size={14} className="alert-icon" />
              <span>{validationError}</span>
            </div>
          )}


          {startError && (
            <div className="launcher-alert alert-error font-onest" role="alert">
              <AlertCircle size={14} className="alert-icon" />
              <span>{startError}</span>
            </div>
          )}

          {/* Mode Banner: Inform user if offline fallback mode is active */}
          {keysMissing && (
            <div
              id="offline-fallback-active-banner"
              className="launcher-alert font-onest"
              role="status"
              style={{
                background: 'rgba(234, 179, 8, 0.08)',
                border: '1px solid rgba(234, 179, 8, 0.3)',
                color: '#facc15',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                borderRadius: '6px',
                fontSize: '12px',
                marginTop: '10px',
              }}
            >
              <span style={{ fontWeight: 700, letterSpacing: '0.04em' }}>⚡ OFFLINE DEMO MODE</span>
              <span style={{ color: 'rgba(255, 255, 255, 0.75)' }}>
                Running deterministic offline AST verification. Pre-approved sample repositories below are ready to evaluate.
              </span>
            </div>
          )}

          {/* Centered Thin Divider with OR */}
          <div className="launcher-divider">
            <span className="divider-line"></span>
            <span className="divider-label font-mono">OR</span>
            <span className="divider-line"></span>
          </div>

          {/* Sample Repository Heading & Description */}
          <div className="sample-repos-section-header">
            <h2 className="sample-repos-title font-oxanium">Use Sample Repository</h2>
            <p className="sample-repos-desc font-onest">
              Choose a pre-approved vulnerable sample repository to test ZeroDay's autonomous detection, exploit reproduction, and 4-gate verification.
            </p>
          </div>

          {/* Three Horizontal Repository Choice Buttons */}
          <div className="repo-choices-row" role="radiogroup" aria-label="Sample Repositories">
            {SAMPLE_REPOSITORIES.map((sample) => {
              const isSelected = selectedCardId === sample.id;
              return (
                <button
                  type="button"
                  key={sample.id}
                  role="radio"
                  aria-checked={isSelected}
                  disabled={isStarting || isValidating}
                  onClick={() => handleSelectSampleChoice(sample)}
                  className={`repo-choice-btn font-onest ${isSelected ? 'selected' : ''}`}
                  id={`choice-${sample.id}`}
                >
                  <div className="choice-text">
                    <span className="choice-title font-onest">{sample.name}</span>
                    <span className="choice-repo-slug font-onest">{sample.repo}</span>
                  </div>
                  {isSelected && isStarting ? (
                    <Loader2 size={15} className="spin-icon text-cyan" />
                  ) : (
                    <span className="choice-arrow" aria-hidden="true">&#x2197;</span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </main>
    </div>
  );
}
