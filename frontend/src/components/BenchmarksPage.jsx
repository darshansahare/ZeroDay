import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Play,
  RefreshCw,
  XCircle,
  FileCode,
  ArrowRight,
  ArrowUpRight,
  ChevronUp,
  ChevronDown,
  ShieldCheck,
  Bug,
  BookOpen,
  Target,
  FileCheck,
  ExternalLink,
  Layers,
  CheckCircle2,
  Copy,
  Check,
  Terminal,
  Search,
  Filter,
  CheckCircle,
} from 'lucide-react';
import { authHeaders, getCsrfToken } from '../utils/csrf';

export default function BenchmarksPage({ onSelectBenchmark, onNavigateToArena }) {
  // Pre-seed with session cache if available to guarantee zero-layout-shift instant smooth transition
  const [data, setData] = useState(() => {
    try {
      const cached = sessionStorage.getItem('zda_benchmarks_cache');
      if (cached) return JSON.parse(cached);
    } catch {
      /* ignore */
    }
    return null;
  });
  const [loading, setLoading] = useState(() => {
    try {
      return !sessionStorage.getItem('zda_benchmarks_cache');
    } catch {
      return true;
    }
  });
  const [error, setError] = useState(null);
  const [runningEvaluation, setRunningEvaluation] = useState(false);
  const [copiedKey, setCopiedKey] = useState(null);
  const casesSectionRef = useRef(null);

  const scrollToTable = () => {
    if (casesSectionRef.current) {
      casesSectionRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else {
      const el = document.getElementById('vulnerability-cases');
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  // Filter state
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  // In-situ inspection state: default to first benchmark expanded
  const [expandedBenchmarkId, setExpandedBenchmarkId] = useState(null);
  const [activeEvidenceTab, setActiveEvidenceTab] = useState('exploit'); // 'exploit' | 'patch' | 'gates' | 'intel'

  // Fetch benchmark suite data from backend
  const fetchBenchmarkData = async (silent = false) => {
    try {
      if (!silent && !data) setLoading(true);
      const res = await fetch('/api/benchmarks', {
        credentials: 'same-origin',
        headers: { 'Cache-Control': 'no-cache' },
      });
      if (!res.ok) throw new Error('Failed to load benchmark registry.');
      const resData = await res.json();
      setData(resData);
      try {
        sessionStorage.setItem('zda_benchmarks_cache', JSON.stringify(resData));
      } catch {
        /* ignore */
      }
      setError(null);
      // All benchmarks stay collapsed by default on load or refresh
    } catch (err) {
      if (!data) setError(err.message || 'Error connecting to benchmark service.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    fetchBenchmarkData(Boolean(data));
  }, []);

  // Trigger Run Evaluation via API
  const handleRunEvaluation = async () => {
    // Smoothly scroll down to the benchmark table below
    scrollToTable();

    if (runningEvaluation) return;
    try {
      setRunningEvaluation(true);
      setError(null);

      // Ensure session & CSRF cookies are primed before POST
      if (!getCsrfToken()) {
        await fetchBenchmarkData(true);
      }

      const res = await fetch('/api/benchmarks/run', {
        method: 'POST',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        credentials: 'same-origin',
        body: JSON.stringify({ suite: 'all' }),
      });
      if (!res.ok) {
        if (res.status === 401) {
          throw new Error('Admin authorization required to run benchmarks. Open Settings to authenticate.');
        }
        throw new Error('Evaluation execution failed.');
      }
      const runRes = await res.json();
      if (runRes.benchmarks && runRes.metrics) {
        setData(runRes);
        try {
          sessionStorage.setItem('zda_benchmarks_cache', JSON.stringify(runRes));
        } catch {
          /* ignore */
        }
        setError(null);
      } else {
        await fetchBenchmarkData(true);
      }
    } catch (err) {
      console.error('Failed to execute evaluation:', err);
      setError(err.message || 'Evaluation execution failed.');
    } finally {
      setRunningEvaluation(false);
    }
  };

  const handleCopyCode = (text, key) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const metrics = data?.metrics || {
    configured_benchmarks: 0,
    executed_test_cases: 0,
    detection_recall_percent: null,
    verified_remediations_count: 0,
    verified_remediation_rate_percent: null,
    false_positives_count: 0,
  };

  const rawBenchmarks = data?.benchmarks || [];

  // Filtered benchmarks calculation (Severity & Status)
  const filteredBenchmarks = useMemo(() => {
    return rawBenchmarks.filter((item) => {
      // 1. Severity filter
      if (severityFilter !== 'ALL') {
        if ((item.severity || '').toUpperCase() !== severityFilter) return false;
      }
      // 2. Status filter
      if (statusFilter !== 'ALL') {
        const itemStatus = (item.status || '').toUpperCase();
        const itemDetection = (item.detection_result || '').toUpperCase();
        if (statusFilter === 'VERIFIED_SECURE') {
          if (
            itemStatus !== 'VERIFIED_SECURE' &&
            item.remediation_result !== 'Remediation verified' &&
            itemStatus !== 'SCAN_COMPLETE_NO_FINDINGS' &&
            itemDetection !== 'NO VULNERABILITIES FOUND'
          ) {
            return false;
          }
        } else if (statusFilter === 'DETECTED') {
          if (itemDetection !== 'DETECTED' && itemStatus !== 'DETECTED') {
            return false;
          }
        } else if (statusFilter === 'CLEAN') {
          if (itemStatus !== 'SCAN_COMPLETE_NO_FINDINGS' && itemDetection !== 'NO VULNERABILITIES FOUND' && !item.is_secure_baseline) {
            return false;
          }
        }
      }
      return true;
    });
  }, [rawBenchmarks, severityFilter, statusFilter]);

  const hasActiveFilters = severityFilter !== 'ALL' || statusFilter !== 'ALL';

  return (
    <div className="benchmarks-page-canvas font-onest">
      {/* Background Engineering Grid */}
      <div className="benchmarks-grid-pattern" aria-hidden="true" />

      <div className="benchmarks-content-wrap">

        {/* Page Header */}
        <header className="benchmarks-header-row">
          <div className="header-text-block">
            <div className="benchmarks-eyebrow font-mono" style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span className="eyebrow-prefix">ZeroDay</span>
              <span className="breadcrumb-sep">/</span>
              <span className="eyebrow-title">Benchmarks</span>
            </div>

            <h1 className="benchmarks-title font-oxanium">
              Vulnerability & Remediation Benchmarks
            </h1>
            <p className="benchmarks-subtitle font-onest">
              Empirical evaluation of ZeroDay's autonomous vulnerability detection, exploit reproduction, and 4-gate verified patch remediation against deterministic test suites.
            </p>
          </div>

          <div className="header-actions-block">
            <button
              type="button"
              onClick={handleRunEvaluation}
              disabled={runningEvaluation}
              className="btn-run-evaluation font-onest"
              title="Run autonomous evaluation against configured test cases"
            >
              {runningEvaluation ? (
                <>
                  <RefreshCw size={14} className="spin-icon" />
                  <span>Evaluating...</span>
                </>
              ) : (
                <>
                  <Play size={14} fill="currentColor" />
                  <span>Run Evaluation</span>
                </>
              )}
            </button>
          </div>
        </header>

        {/* Minimal Unboxed Metrics Summary Strip */}
        <div className="benchmarks-metrics-strip font-onest" aria-label="Suite Metrics Summary">
          <div className="metric-strip-item">
            <span className="metric-strip-label font-mono">TOTAL TEST CASES</span>
            <span className="metric-strip-value font-oxanium text-white">
              {metrics.configured_benchmarks ?? rawBenchmarks.length ?? 0}
            </span>
          </div>

          <div className="metric-strip-divider" aria-hidden="true" />

          <div className="metric-strip-item">
            <span className="metric-strip-label font-mono">VULNERABILITY FOUND</span>
            <span className="metric-strip-value font-oxanium text-accent">
              {metrics.detected_vulnerabilities_count ?? (metrics.vulnerable_targets_count ?? 0)}
              <span className="metric-strip-denominator">/{metrics.configured_benchmarks ?? rawBenchmarks.length ?? 0}</span>
            </span>
          </div>

          <div className="metric-strip-divider" aria-hidden="true" />

          <div className="metric-strip-item">
            <span className="metric-strip-label font-mono">SUCCESSFUL RUN</span>
            <span className="metric-strip-value font-oxanium text-emerald">
              {metrics.executed_test_cases ?? (rawBenchmarks.length || 0)}
              <span className="metric-strip-denominator">/{metrics.configured_benchmarks ?? rawBenchmarks.length ?? 0}</span>
            </span>
          </div>

          <div className="metric-strip-divider" aria-hidden="true" />

          <div className="metric-strip-item">
            <span className="metric-strip-label font-mono">VERIFIED FIXES</span>
            <span className="metric-strip-value font-oxanium text-emerald">
              {metrics.verified_remediations_count ?? 0}
              <span className="metric-strip-denominator">/{metrics.vulnerable_targets_count ?? 0}</span>
            </span>
          </div>
        </div>

        {/* Vulnerability Cases & Filter Bar */}
        <section id="vulnerability-cases" ref={casesSectionRef} className="benchmarks-cases-section" aria-label="Vulnerability Cases">

          <div className="section-header-bar">
            <div>
              <h2 className="section-heading font-onest">Vulnerability Cases</h2>
              <p className="section-subheading font-onest">
                Configured test fixtures evaluated against AST sink invariants and autonomous remediation gates.
              </p>
            </div>
          </div>

          {/* Filter controls row (below heading and description) */}
          <div className="benchmarks-filter-row">
            {/* Severity Dropdown */}
            <div className="filter-select-item">
              <span className="filter-select-label font-mono">SEVERITY:</span>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="filter-select font-onest"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            {/* Status Dropdown */}
            <div className="filter-select-item">
              <span className="filter-select-label font-mono">STATUS:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="filter-select font-onest"
              >
                <option value="ALL">All Statuses</option>
                <option value="VERIFIED_SECURE">Verified Secure</option>
                <option value="DETECTED">Detected</option>
              </select>
            </div>

            {/* Reset Filters Button */}
            {hasActiveFilters && (
              <button
                type="button"
                onClick={() => {
                  setSeverityFilter('ALL');
                  setStatusFilter('ALL');
                }}
                className="btn-reset-filters font-onest"
                title="Reset all filters"
              >
                Clear Filters
              </button>
            )}
          </div>

          {/* Content States & Table */}
          {loading ? (
            <div className="benchmarks-state-box font-onest">
              <RefreshCw size={18} className="spin-icon text-muted mb-2" />
              <div className="text-muted">Loading benchmark cases...</div>
            </div>
          ) : error ? (
            <div className="benchmarks-state-box font-onest">
              <XCircle size={22} className="text-crimson mb-2" />
              <div className="text-white font-medium">Error loading benchmarks</div>
              <div className="text-muted mb-3 text-sm">{error}</div>
              <button type="button" onClick={fetchBenchmarkData} className="btn-retry font-onest">
                Retry Connection
              </button>
            </div>
          ) : rawBenchmarks.length === 0 ? (
            <div className="benchmarks-state-box font-onest">
              <div className="empty-title font-onest">No benchmarks configured</div>
              <div className="empty-desc font-onest">
                Explicitly supply benchmark targets to the registry to evaluate ZeroDay's autonomous detection and verified remediation.
              </div>
            </div>
          ) : filteredBenchmarks.length === 0 ? (
            <div className="benchmarks-state-box font-onest">
              <Filter size={20} className="text-muted mb-2" />
              <div className="empty-title font-onest">No matching benchmark cases</div>
              <div className="empty-desc font-onest">
                No cases match your active severity or status filters.
              </div>
              <button
                type="button"
                onClick={() => {
                  setSeverityFilter('ALL');
                  setStatusFilter('ALL');
                }}
                className="btn-retry font-onest"
              >
                Reset Filters
              </button>
            </div>
          ) : (
            <div className="benchmarks-table-shell">
              <table className="benchmarks-table">
                <thead>
                  <tr>
                    <th className="font-onest col-benchmark" style={{ width: '38%' }}>Benchmark</th>
                    <th className="font-onest col-cwe" style={{ width: '15%', textAlign: 'center', verticalAlign: 'middle' }}>CWE</th>
                    <th className="font-onest col-severity" style={{ width: '15%', textAlign: 'center', verticalAlign: 'middle' }}>Severity</th>
                    <th className="font-onest col-status" style={{ width: '18%', textAlign: 'center', verticalAlign: 'middle' }}>Status</th>
                    <th className="font-onest col-action" style={{ width: '14%', textAlign: 'center', verticalAlign: 'middle' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredBenchmarks.map((item) => {
                    const isExpanded = expandedBenchmarkId === item.id;
                    return (
                      <React.Fragment key={item.id}>
                        <tr
                          onClick={() => setExpandedBenchmarkId(isExpanded ? null : item.id)}
                          className={`benchmarks-row ${isExpanded ? 'row-active' : ''}`}
                          tabIndex={0}
                          role="button"
                          aria-expanded={isExpanded}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              setExpandedBenchmarkId(isExpanded ? null : item.id);
                            }
                          }}
                        >
                          {/* 1. Benchmark Title */}
                          <td className="col-benchmark">
                            <span className="case-title font-onest">{item.title}</span>
                          </td>

                          {/* 2. CWE */}
                          <td className="col-cwe" style={{ textAlign: 'center', verticalAlign: 'middle' }}>
                            <span className="case-cwe-clean font-mono" style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', textAlign: 'center' }}>{item.cwe}</span>
                          </td>

                          {/* 3. Severity */}
                          <td className="col-severity" style={{ textAlign: 'center', verticalAlign: 'middle' }}>
                            <span className={`case-severity-clean severity-${(item.severity || 'high').toLowerCase()} font-onest`} style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', textAlign: 'center' }}>
                              {item.severity}
                            </span>
                          </td>

                          {/* 4. Status */}
                          <td className="col-status" style={{ textAlign: 'center', verticalAlign: 'middle' }}>
                            <span className={`case-status-text font-onest ${item.detection_result === 'No vulnerabilities found' || item.status === 'SCAN_COMPLETE_NO_FINDINGS' ? 'case-status-clean' : item.status === 'UNDETECTED' || item.detection_result === 'Not detected' ? 'text-muted' : ''}`} style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', textAlign: 'center' }}>
                              {item.detection_result === 'No vulnerabilities found' || item.status === 'SCAN_COMPLETE_NO_FINDINGS'
                                ? 'No vulnerabilities found'
                                : item.status === 'VERIFIED_SECURE' || item.remediation_result === 'Remediation verified'
                                  ? 'Verified Secure'
                                  : item.status === 'UNDETECTED' || item.detection_result === 'Not detected'
                                    ? 'Undetected (Out of AST Scope)'
                                    : item.status === 'ERROR' || item.status === 'INCOMPLETE'
                                      ? (item.status === 'ERROR' ? 'Scan Error' : 'Incomplete')
                                      : (item.detection_result || 'Detected')}
                            </span>
                          </td>

                          {/* 5. Action */}
                          <td className="col-action" style={{ textAlign: 'center', verticalAlign: 'middle' }}>
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                setExpandedBenchmarkId(isExpanded ? null : item.id);
                              }}
                              className={`btn-inspect-action font-onest ${isExpanded ? 'action-active' : ''}`} style={{ margin: '0 auto', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', textAlign: 'center' }}
                              title="Inspect benchmark analysis"
                            >
                              <span>Inspect</span>
                              {isExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                            </button>
                          </td>
                        </tr>

                        {/* Expandable Agent Breakdown & Threat Intel */}
                        {isExpanded && (
                          <tr className="inspection-expanded-row">
                            <td colSpan={5} className="inspection-expanded-cell">
                              {(item.is_secure_baseline || item.cwe === 'CLEAN' || item.status === 'SCAN_COMPLETE_NO_FINDINGS' || item.detection_result === 'No vulnerabilities found' || item.detection_result === 'No Vulnerability found') ? (
                                <div className="clean-inspection-text font-onest">
                                  No Vulnerability found
                                </div>
                              ) : (
                                <div className="inspection-workspace font-onest">
                                  {/* 1. Side-by-Side Agent Explanations (Proper Dark Cards) */}
                                  <div className="inspection-agents-grid">
                                    {/* Red Team Agent Box */}
                                    <div className="agent-text-box agent-box-red">
                                      <span className="agent-title-red font-oxanium">Red Team Agent</span>
                                      <p className="agent-description-text font-onest">
                                        {item.red_team_analysis || item.description || item.actual_finding || 'Red team exploit analysis.'}
                                      </p>
                                    </div>

                                    {/* Blue Team Agent Box */}
                                    <div className="agent-text-box agent-box-blue">
                                      <span className="agent-title-blue font-oxanium">Blue Team Agent</span>
                                      <p className="agent-description-text font-onest">
                                        {item.blue_team_analysis || item.remediation_result || 'Blue team remediation.'}
                                      </p>
                                    </div>
                                  </div>

                                  {/* 2. Tavily Threat Intelligence & Documentation Retrieved */}
                                  <div className="tavily-intel-section">
                                    <div className="tavily-intel-header">
                                      <span className="tavily-title font-oxanium">Tavily Threat Intelligence</span>
                                    </div>

                                    <div className="tavily-docs-grid">
                                      {item.intelligence_references && item.intelligence_references.length > 0 ? (
                                        item.intelligence_references.map((ref, idx) => (
                                          <div key={idx} className="tavily-doc-box font-onest">
                                            <div className="tavily-doc-top">
                                              <div className="tavily-doc-meta">
                                                <span className="tavily-cwe-tag font-mono">{ref.cwe_id || item.cwe}</span>
                                                <span className="tavily-doc-title font-onest">{ref.title}</span>
                                              </div>
                                              {ref.source_url && (
                                                <a
                                                  href={ref.source_url}
                                                  target="_blank"
                                                  rel="noopener noreferrer"
                                                  className="tavily-doc-link font-onest"
                                                  title="Open official documentation"
                                                >
                                                  <span>Docs</span>
                                                  <ExternalLink size={11} />
                                                </a>
                                              )}
                                            </div>
                                            <p className="tavily-doc-excerpt font-onest">{ref.excerpt}</p>
                                          </div>
                                        ))
                                      ) : (
                                        <div className="tavily-doc-empty font-onest text-muted" style={{ padding: '12px', fontSize: '0.85rem' }}>
                                          No threat intelligence advisories loaded for this benchmark case.
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              )}
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody></table>
            </div>
          )}
        </section>

      </div>
    </div>
  );
}