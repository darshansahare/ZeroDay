import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
  ArrowLeft,
  ArrowUpRight,
} from 'lucide-react';
/**
 * GitHub repository bookmark icon matching GitHub's native repo header
 */
function RepoBookmarkIcon({ size = 18, className = "" }) {
  return (
    <svg
      aria-hidden="true"
      height={size}
      viewBox="0 0 16 16"
      version="1.1"
      width={size}
      fill="currentColor"
      className={className}
    >
      <path d="M2 2.5A2.5 2.5 0 0 1 4.5 0h8.75a.75.75 0 0 1 .75.75v12.5a.75.75 0 0 1-.75.75h-2.5a.75.75 0 0 1 0-1.5h1.75v-2h-8a1 1 0 0 0-.714 1.7.75.75 0 1 1-1.072 1.05A2.495 2.495 0 0 1 2 11.5Zm10.5-1h-8a1 1 0 0 0-1 1v6.708A2.486 2.486 0 0 1 4.5 9h8ZM5 12.25a.25.25 0 0 1 .25-.25h3.5a.25.25 0 0 1 .25.25v3.25a.25.25 0 0 1-.4.2l-1.45-1.087a.249.249 0 0 0-.3 0L5.4 15.7a.25.25 0 0 1-.4-.2Z"></path>
    </svg>
  );
}
/**
 * Extracts clean domain name from URL (e.g. 'safeguard.sh')
 */
function getDomainFromUrl(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    return parsed.hostname.replace(/^www\./, '');
  } catch (e) {
    return url;
  }
}
/**
 * Parses repo owner and name from GitHub URL or target path
 */
function parseRepoInfo(url) {
  if (!url) {
    return {
      name: 'zeroday-test-1',
      owner: 'darshansahare',
      url: 'https://github.com/darshansahare/zeroday-test-1',
    };
  }
  try {
    const clean = url.replace(/\.git$/, '').replace(/\/$/, '');
    const parts = clean.split('/');
    if (parts.length >= 2) {
      const name = parts[parts.length - 1];
      const owner = parts[parts.length - 2];
      return { name, owner, url };
    }
  } catch (e) { }
  return {
    name: 'zeroday-test-1',
    owner: 'darshansahare',
    url: url || 'https://github.com/darshansahare/zeroday-test-1',
  };
}
/**
 * Detects the repository's vulnerability metadata dynamically based on:
 * 1. Active run findings (cwe, vulnerability_class, title, description)
 * 2. Run report summary or status
 * 3. Repository URL or name (e.g. zeroday-test-1, zeroday-test-2, zeroday-test-3)
 */
function getVulnerabilityMeta(repoInfo, runSummary, runReport, comparisonData) {
  const firstFinding = runReport?.code_findings?.[0] || comparisonData?.findings?.[0];
  const firstRef = runReport?.intelligence_references?.[0];
  const findingCwe = (firstFinding?.cwe || firstRef?.cwe_id || '').toUpperCase();
  const findingTitle = firstFinding?.title || firstFinding?.vulnerability_class || '';
  // Clean Repository (No vulnerabilities detected in scanned scope)
  const isClean =
    runSummary?.status === 'SCAN_COMPLETE_NO_FINDINGS' ||
    runReport?.final_status === 'SCAN_COMPLETE_NO_FINDINGS' ||
    (runReport && Array.isArray(runReport.code_findings) && runReport.code_findings.length === 0);
  if (isClean) {
    return {
      cwe: 'CLEAN',
      vulnType: 'No Vulnerabilities Detected',
      description: 'Scan Complete: No vulnerabilities detected in scanned scope. The repository passed all static AST security invariant checks with zero findings.',
    };
  }
  return {
    cwe: findingCwe || (runSummary?.status === 'ANALYZING' ? 'SCANNING...' : 'DETECTING...'),
    vulnType: findingTitle ? String(findingTitle).replace(/_/g, ' ') : (runSummary?.status === 'ANALYZING' ? 'Static AST Analysis In Progress' : 'Security Vulnerability Inspection'),
    description: firstFinding?.description || runReport?.summary || runSummary?.summary || 'Autonomous security remediation workspace.',
  };
}
/**
 * Skeleton Loading Page
 */
function ArenaRunSkeleton({ onNavigateBack }) {
  return (
    <div className="arena-run-page skeleton-page">
      <div className="run-content-wrapper">
        {/* Back Link Skeleton */}
        <div className="run-top-nav">
          <div className="skeleton-line-bar" style={{ width: '130px', height: '14px' }} />
        </div>
        {/* Header Skeleton */}
        <div className="run-repo-header" style={{ marginBottom: '32px' }}>
          <div className="skeleton-line-bar" style={{ width: '260px', height: '26px', marginBottom: '14px' }} />
          <div className="skeleton-line-bar" style={{ width: '85%', maxWidth: '640px', height: '16px', marginBottom: '8px' }} />
          <div className="skeleton-line-bar" style={{ width: '60%', maxWidth: '440px', height: '16px' }} />
        </div>
        {/* Code Grid Skeleton */}
        <div className="code-comparison-grid" style={{ marginBottom: '44px' }}>
          {/* Left Red Box Skeleton */}
          <div className="code-column-card skeleton-card">
            <div className="code-column-header">
              <div className="skeleton-line-bar" style={{ width: '200px', height: '16px' }} />
            </div>
            <div className="code-viewer-body">
              {[...Array(13)].map((_, i) => (
                <div
                  key={i}
                  className={`skeleton-code-line ${i === 6 || i === 7 ? 'skeleton-row-red' : ''}`}
                >
                  <div className="skeleton-line-bar" style={{ width: '20px', height: '11px', flexShrink: 0 }} />
                  <div
                    className="skeleton-line-bar"
                    style={{
                      width: `${35 + ((i * 17) % 55)}%`,
                      height: '11px',
                    }}
                  />
                </div>
              ))}
            </div>
          </div>
          {/* Right Blue Box Skeleton */}
          <div className="code-column-card skeleton-card">
            <div className="code-column-header">
              <div className="skeleton-line-bar" style={{ width: '200px', height: '16px' }} />
            </div>
            <div className="code-viewer-body">
              {[...Array(13)].map((_, i) => (
                <div
                  key={i}
                  className={`skeleton-code-line ${i === 6 || i === 7 ? 'skeleton-row-blue' : ''}`}
                >
                  <div className="skeleton-line-bar" style={{ width: '20px', height: '11px', flexShrink: 0 }} />
                  <div
                    className="skeleton-line-bar"
                    style={{
                      width: `${40 + ((i * 23) % 50)}%`,
                      height: '11px',
                    }}
                  />
                </div>
              ))}
            </div>
          </div>
        </div>
        {/* Documentation Skeleton */}
        <div className="docs-section">
          <div className="skeleton-line-bar" style={{ width: '200px', height: '22px', marginBottom: '6px' }} />
          <div className="skeleton-line-bar" style={{ width: '320px', height: '13px', marginBottom: '20px' }} />
          <div className="docs-grid">
            {[1, 2, 3].map((n) => (
              <div key={n} className="doc-card skeleton-card">
                <div className="skeleton-line-bar" style={{ width: '75%', height: '16px', marginBottom: '10px' }} />
                <div className="skeleton-line-bar" style={{ width: '30%', height: '11px', marginBottom: '12px' }} />
                <div className="skeleton-line-bar" style={{ width: '100%', height: '11px', marginBottom: '6px' }} />
                <div className="skeleton-line-bar" style={{ width: '85%', height: '11px', marginBottom: '6px' }} />
                <div className="skeleton-line-bar" style={{ width: '55%', height: '11px' }} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
/**
 * Syntax Code Viewer for Red Team and Blue Team columns
 */
function CodeBlockViewer({
  title,
  agentType, // 'red' | 'blue'
  code,
  highlightedLines = [],
  emptyMessage,
  isLoading = false,
}) {
  const codeContainerRef = useRef(null);
  const lines = useMemo(() => {
    if (!code) return [];
    return code.split('\n');
  }, [code]);
  const highlightSet = useMemo(() => new Set(highlightedLines), [highlightedLines]);
  return (
    <div className={`code-column-card code-card-${agentType}`}>
      {/* Column Header */}
      <div className="code-column-header">
        <div className="code-column-title-group">
          <span className="code-column-title font-oxanium">{title}</span>
        </div>
      </div>
      {/* Code Viewer Body */}
      <div className="code-viewer-body" ref={codeContainerRef}>
        {isLoading ? (
          <div className="code-loading-placeholder font-onest">
            <span className="agent-spinner" />
            <span>Blue Agent synthesizing deterministic patch...</span>
          </div>
        ) : lines.length > 0 ? (
          <div className="code-lines-table monospace">
            {lines.map((lineText, idx) => {
              const lineNum = idx + 1;
              const isHighlighted = highlightSet.has(lineNum);
              return (
                <div
                  key={lineNum}
                  className={`code-line-row ${isHighlighted ? `line-highlight-${agentType}` : ''}`}
                >
                  <span className="code-line-num">{lineNum}</span>
                  <span className="code-line-text">{lineText || ' '}</span>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="code-empty-state font-onest">
            {emptyMessage || 'No code available'}
          </div>
        )}
      </div>
    </div>
  );
}
/**
 * Main Redesigned Arena Run Page
 */
export default function ArenaRunWorkspace({
  runId,
  initialRunSummary = null,
  onNavigateBack,
  openConfigModal,
  runtimeConfig,
}) {
  const [runSummary, setRunSummary] = useState(initialRunSummary);
  const [runReport, setRunReport] = useState(null);
  const [comparisonData, setComparisonData] = useState(null);
  const [isLoading, setIsLoading] = useState(!initialRunSummary);
  const [fetchError, setFetchError] = useState('');
  const [liveTavilyRefs, setLiveTavilyRefs] = useState([]);
  const pollIntervalRef = useRef(null);
  // Fetch run status, report, and code comparison
  const fetchRunData = useCallback(async () => {
    if (!runId) return;
    try {
      // 1. Fetch Summary
      const summaryRes = await fetch(`/api/runs/${runId}`).catch(() => null);
      if (summaryRes && summaryRes.ok) {
        const sumData = await summaryRes.json();
        setRunSummary(sumData);
      }
      // 2. Fetch Comparison
      const compRes = await fetch(`/api/runs/${runId}/comparison`).catch(() => null);
      if (compRes && compRes.ok) {
        const compData = await compRes.json();
        setComparisonData(compData);
      }
      // 3. Fetch Evidence Report if available
      const repRes = await fetch(`/api/runs/${runId}/report`).catch(() => null);
      if (repRes && repRes.ok) {
        const repData = await repRes.json();
        setRunReport(repData);
      }
      setIsLoading(false);
    } catch (err) {
      console.error('Error polling run data:', err);
      setFetchError(err.message || 'Failed to load run data');
      setIsLoading(false);
    }
  }, [runId]);
  // Polling management: polls while run is actively executing
  useEffect(() => {
    if (!initialRunSummary) {
      setIsLoading(true);
    }
    fetchRunData();
    pollIntervalRef.current = setInterval(() => {
      fetchRunData();
    }, 1500);
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [fetchRunData, initialRunSummary]);
  // Stop polling once finalized, ensuring final report is fetched
  useEffect(() => {
    const finalStates = ['ACCEPTED', 'VERIFIED_SECURE', 'SCAN_COMPLETE_NO_FINDINGS', 'REJECTED', 'FAILED', 'TIMED_OUT', 'CANCELLED'];
    if (runSummary?.status && finalStates.includes(runSummary.status)) {
      const timer = setTimeout(() => {
        fetchRunData();
        if (pollIntervalRef.current) {
          clearInterval(pollIntervalRef.current);
        }
      }, 600);
      return () => clearTimeout(timer);
    }
  }, [runSummary?.status, fetchRunData]);
  // Parse repo info
  const repoInfo = useMemo(() => {
    const rawUrl = runSummary?.repo_url || runReport?.repo_url || '';
    return parseRepoInfo(rawUrl);
  }, [runSummary?.repo_url, runReport?.repo_url]);
  // Detect vulnerability metadata dynamically based on repo and run data
  const vulnMeta = useMemo(() => {
    return getVulnerabilityMeta(repoInfo, runSummary, runReport, comparisonData);
  }, [repoInfo, runSummary, runReport, comparisonData]);
  // Compute vulnerable and patched code
  const codeComparison = useMemo(() => {
    let vulnCode = comparisonData?.vulnerable_code || runReport?.vulnerable_code || '';
    let vulnLines = comparisonData?.vulnerable_lines || runReport?.vulnerable_lines || [];
    let patchCode = comparisonData?.patched_code || runReport?.patched_code || '';
    let patchLines = comparisonData?.patched_lines || runReport?.patched_lines || [];
    // Fallback to primary finding snippet if comparison hasn't returned yet
    if (!vulnCode && runReport?.code_findings?.[0]?.code_snippet) {
      vulnCode = runReport.code_findings[0].code_snippet;
    }
    // Vulnerable lines set: filter backend lines to avoid marking imports
    const computedVulnSet = new Set(vulnLines.filter((l) => l > 3 || vulnLines.length <= 5));
    // Patched lines set: start with backend-provided line numbers
    const computedPatchSet = new Set(patchLines);
    // Compute highlighted remediation lines if patch exists
    if (patchCode) {
      const vLines = vulnCode ? vulnCode.split('\n').map((l) => l.trim()) : [];
      const pLines = patchCode.split('\n');
      pLines.forEach((line, idx) => {
        const trimmed = line.trim();
        const lNum = idx + 1;
        if (trimmed && !vLines.includes(trimmed) && (lNum > 3 || computedPatchSet.has(lNum))) {
          computedPatchSet.add(lNum);
        }
      });
    }
    return {
      vulnCode,
      vulnLines: Array.from(computedVulnSet).sort((a, b) => a - b),
      patchCode,
      patchLines: Array.from(computedPatchSet).sort((a, b) => a - b),
      hasPatch: Boolean(patchCode),
    };
  }, [comparisonData, runReport]);
  // Live Tavily Search integration: fetch real-time threat intelligence if not yet in report
  useEffect(() => {
    const cwe = vulnMeta.cwe;
    if (!cwe || cwe === 'CLEAN' || cwe === 'SCANNING...' || cwe.includes('DETECT')) return;
    const existing = runReport?.intelligence_references || comparisonData?.intelligence_references || liveTavilyRefs;
    if (existing && existing.length > 0) return;
    let isMounted = true;
    const query = `${cwe} vulnerability python explanation and remediation`;
    fetch(`/api/intel/guidance?query=${encodeURIComponent(query)}&cwe=${encodeURIComponent(cwe)}`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (isMounted && data && Array.isArray(data.references) && data.references.length > 0) {
          setLiveTavilyRefs(data.references);
        }
      })
      .catch(() => {});
    return () => {
      isMounted = false;
    };
  }, [vulnMeta.cwe, runReport?.intelligence_references, comparisonData?.intelligence_references, liveTavilyRefs]);
  // Compute Documentation List (Real-time Tavily threat intelligence)
  const documentationList = useMemo(() => {
    const rawRefs = runReport?.intelligence_references || comparisonData?.intelligence_references || liveTavilyRefs || [];
    if (rawRefs.length > 0) {
      return rawRefs.map((ref) => ({
        title: ref.title || 'Security Advisory & Remediation Guidance',
        source_url: ref.source_url || 'https://cwe.mitre.org',
        excerpt: ref.excerpt || 'Security advisory detailing root cause analysis and patch recommendations.',
        cwe_id: ref.cwe_id || vulnMeta.cwe,
        source_provider: ref.source_provider || 'tavily',
      }));
    }
    return [];
  }, [runReport?.intelligence_references, comparisonData?.intelligence_references, liveTavilyRefs, vulnMeta.cwe]);
  // Meaningful vulnerability explanation: synthesized from live Tavily threat intelligence (max 3 lines)
  const vulnerabilityInfo = useMemo(() => {
    const allRefs = runReport?.intelligence_references || comparisonData?.intelligence_references || liveTavilyRefs || [];
    const firstRef = allRefs[0];
    const firstFinding = runReport?.code_findings?.[0] || comparisonData?.findings?.[0];

    // Clean Repository Case
    const isClean =
      vulnMeta.cwe === 'CLEAN' ||
      runSummary?.status === 'SCAN_COMPLETE_NO_FINDINGS' ||
      runReport?.final_status === 'SCAN_COMPLETE_NO_FINDINGS' ||
      (runReport && Array.isArray(runReport.code_findings) && runReport.code_findings.length === 0);
    if (isClean) {
      return {
        name: 'No Vulnerabilities Detected',
        meaning: 'AST reconnaissance verified zero vulnerable sinks across the analyzed repository scope. All baseline security invariants were satisfied.',
      };
    }

    // Determine clean vulnerability title
    const cwe = firstFinding?.cwe || firstRef?.cwe_id || (vulnMeta.cwe && vulnMeta.cwe !== 'DETECTING...' && vulnMeta.cwe !== 'SCANNING...' ? vulnMeta.cwe : 'CWE-89');
    let rawTitle = firstFinding?.title || firstFinding?.vulnerability_class || vulnMeta.vulnType || firstRef?.title || 'Security Vulnerability';
    let cleanTitle = String(rawTitle)
      .replace(/_/g, ' ')
      .replace(/^CWE-\d+:\s*/i, '')
      .split(/\s+[|•–—]\s+/)[0]
      .replace(/\s+/g, ' ')
      .trim();
    if (cleanTitle.toLowerCase().includes('present sql injection')) {
      cleanTitle = 'SQL Injection';
    }
    const name = `[${cwe}] ${cleanTitle}`;

    // Sourced LIVE from Tavily Threat Intelligence
    if (firstRef && firstRef.excerpt) {
      let rawExcerpt = firstRef.excerpt || '';
      let cleaned = rawExcerpt
        .replace(/```[\s\S]*?```/g, '')
        .replace(/`[^`]*`/g, '')
        .replace(/#{1,6}\s+/g, '')
        .replace(/\[\.\.\.\]|\(\.\.\.\)/g, '')
        .replace(/\b(?:e\.g\.|i\.e\.)\s*\.?/gi, '')
        .replace(/\s+/g, ' ')
        .trim();

      let sentences = cleaned.match(/[^.!?]+[.!?]+/g) || [cleaned];
      sentences = sentences
        .map((s) => s.trim())
        .filter((s) => s.length > 25 && !s.startsWith('http') && !s.includes('{'));

      let meaning = sentences.slice(0, 2).join(' ');
      if (!meaning || meaning.length < 30) {
        meaning = cleaned;
      }
      if (meaning.length > 215) {
        let cut = meaning.slice(0, 212);
        let lastSpace = cut.lastIndexOf(' ');
        if (lastSpace > 150) cut = cut.slice(0, lastSpace);
        meaning = cut.replace(/[,\s.]+$/, '') + '.';
      }
      return { name, meaning };
    }

    // In-flight status description while analysis proceeds
    const status = runSummary?.status || 'INITIALIZING';
    if (status === 'ANALYZING' || status === 'SCANNING' || status === 'INITIATED') {
      return {
        name: 'AST Security Analysis in Progress',
        meaning: 'Scanning repository syntax trees and call graphs to identify potential security vulnerabilities and unvalidated sinks.',
      };
    }
    if (status === 'EVIDENCE_GATHERING') {
      return {
        name: 'Tavily Threat Intelligence Search',
        meaning: 'Querying Tavily AI Search Engine live for real-time CVE advisories and mitigation standards...',
      };
    }
    if (status === 'REPRODUCING') {
      return {
        name: 'Red Team Exploit Reproduction',
        meaning: 'Executing an isolated adversarial proof-of-concept against the target service to confirm exploitability.',
      };
    }
    if (status === 'PATCHING') {
      return {
        name: 'Blue Team Patch Synthesis',
        meaning: 'Generating an AST-level defense-in-depth remediation patch with parameterization to eliminate the vulnerable sink.',
      };
    }
    if (status === 'VERIFYING') {
      return {
        name: '4-Gate Invariant Verification',
        meaning: 'Executing independent verification gates to mathematically prove the patch neutralizes the exploit with zero regressions.',
      };
    }

    // Dynamic finding fallback from AST scanner
    if (firstFinding) {
      let meaning = firstFinding.description || 'Vulnerability detected in source code sink. Parameter validation or authorization checks are missing.';
      if (meaning.length > 215) {
        let cut = meaning.slice(0, 212);
        let lastSpace = cut.lastIndexOf(' ');
        if (lastSpace > 150) cut = cut.slice(0, lastSpace);
        meaning = cut.replace(/[,\s.]+$/, '') + '.';
      }
      return { name, meaning };
    }

    return {
      name: 'Security Vulnerability Inspection',
      meaning: 'Autonomous Red Team and Blue Team adversarial verification workspace analyzing repository security.',
    };
  }, [runReport, runSummary, comparisonData, liveTavilyRefs, vulnMeta]);
  // Render Skeleton while initial loading
  if (isLoading && !runSummary && !fetchError) {
    return <ArenaRunSkeleton onNavigateBack={onNavigateBack} />;
  }
  return (
    <div className="arena-run-page">
      <div className="run-content-wrapper">
        {/* Navigation Back Link */}
        <div className="run-top-nav">
          <button
            onClick={onNavigateBack}
            className="run-back-button font-onest"
            aria-label="Back to Target Selection"
          >
            <ArrowLeft size={16} />
            <span>Back to Target Selection</span>
          </button>
        </div>
        {/* 1. Repository Header: [Bookmark Icon] owner / repo-name (Accent color, underline on hover, stationary arrow) */}
        <header className="run-repo-header">
          <div className="repo-title-wrapper" style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <a
              href={repoInfo.url}
              target="_blank"
              rel="noopener noreferrer"
              className="repo-github-link font-oxanium"
              title={`Open ${repoInfo.owner}/${repoInfo.name} on GitHub`}
            >
              <RepoBookmarkIcon size={20} className="repo-header-icon" />
              <span className="repo-full-slug">
                <span className="repo-owner-part">{repoInfo.owner}</span>
                <span className="repo-slash-part"> / </span>
                <span className="repo-name-part">{repoInfo.name}</span>
              </span>
              <ArrowUpRight size={18} className="repo-arrow-icon" aria-hidden="true" />
            </a>
          </div>
          {/* Truthful Execution Mode Badge */}
          {(runReport?.execution_mode || runSummary?.execution_mode) === 'deterministic_offline_fallback' && (
            <div
              id="execution-mode-fallback-badge"
              className="execution-mode-badge font-mono"
              title="Remediation generated via deterministic AST invariant synthesis without external LLM credentials."
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '4px 10px',
                borderRadius: '4px',
                background: 'rgba(234, 179, 8, 0.12)',
                border: '1px solid rgba(234, 179, 8, 0.35)',
                color: '#facc15',
                fontSize: '11px',
                fontWeight: 600,
                marginTop: '6px',
                marginBottom: '10px',
                letterSpacing: '0.04em',
              }}
            >
              <span>⚡ DETERMINISTIC OFFLINE FALLBACK</span>
              <span style={{ color: 'rgba(255, 255, 255, 0.65)', fontWeight: 400 }}>
                &bull; AST Invariant Synthesis (Offline / No Live LLM Call)
              </span>
            </div>
          )}
          <div className="repo-vuln-description font-onest">
            <p className="vuln-description-text" style={{ margin: 0, lineHeight: 1.55 }}>
              <span style={{ color: '#F2F2F0', fontWeight: 600 }}>
                {vulnerabilityInfo.name}:
              </span>{' '}
              <span style={{ color: '#A6AFBD' }}>
                {vulnerabilityInfo.meaning}
              </span>
            </p>
          </div>
        </header>
        {/* Clean Case vs Vulnerable Case Workspace */}
        {
          vulnMeta.cwe === 'CLEAN' ? (
            <div className="clean-inspection-text font-onest" style={{ padding: '30px 0', fontSize: '14px', borderTop: 'none' }}>
              No Vulnerability found
            </div>
          ) : (
            <>
              {/* 2. Side-by-Side Real Code (Red Agent vs Blue Agent) */}
              <section className="code-comparison-section" aria-label="Code comparison: Red Team vs Blue Team">
                <div className="code-comparison-grid">
                  {/* Left: Red Agent Reproduced Vulnerable Code */}
                  <CodeBlockViewer
                    title="Red Agent : Reproduced Vulnerability"
                    agentType="red"
                    code={codeComparison.vulnCode}
                    highlightedLines={codeComparison.vulnLines}
                    emptyMessage="Awaiting repository ingestion and Red Team vulnerability reproduction..."
                  />
                  {/* Right: Blue Agent Corrected / Patched Code */}
                  <CodeBlockViewer
                    title="Blue Agent : Corrected Code"
                    agentType="blue"
                    code={codeComparison.patchCode}
                    highlightedLines={codeComparison.patchLines}
                    emptyMessage="Awaiting Blue Team patch synthesis via NVIDIA Nemotron..."
                    isLoading={!codeComparison.hasPatch && ['ANALYZING', 'EVIDENCE_GATHERING', 'REPRODUCING', 'PATCHING', 'VERIFYING'].includes(runSummary?.status)}
                  />
                </div>
              </section>
              {/* 3. Documentation Found Section */}
              {documentationList.length > 0 ? (
                <section className="docs-section" aria-label="Threat intelligence and security documentation">
                  <div className="docs-section-header">
                    <h2 className="docs-section-title font-oxanium">Live Threat Intelligence</h2>
                    <p className="docs-section-subtitle font-onest">
                      Authoritative security intelligence retrieved via live Tavily search grounding & CWE advisories.
                    </p>
                  </div>
                  <div className="docs-grid">
                    {documentationList.map((doc, idx) => (
                      <article key={idx} className="doc-card">
                        <div className="doc-card-header">
                          <a
                            href={doc.source_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="doc-card-title-link font-oxanium"
                            title={`Open ${doc.title}`}
                          >
                            {doc.title}
                            <ArrowUpRight size={14} className="doc-link-arrow" aria-hidden="true" />
                          </a>
                        </div>
                        <div className="doc-card-meta font-mono">
                          {doc.cwe_id && <span className="doc-tag-cwe">{doc.cwe_id}</span>}
                          <span className="doc-domain-text">{getDomainFromUrl(doc.source_url)}</span>
                        </div>
                        <p className="doc-card-excerpt font-onest">
                          {doc.excerpt}
                        </p>
                      </article>
                    ))}
                  </div>
                </section>
              ) : ['ANALYZING', 'EVIDENCE_GATHERING', 'REPRODUCING'].includes(runSummary?.status) ? (
                <section className="docs-section" aria-label="Threat intelligence search">
                  <div className="docs-section-header">
                    <h2 className="docs-section-title font-oxanium">Live Threat Intelligence</h2>
                    <p className="docs-section-subtitle font-onest">
                      Querying real-time vulnerability advisories via Tavily Search Engine...
                    </p>
                  </div>
                </section>
              ) : null}
            </>
          )
        }
      </div >
    </div >
  );
}
