import React, { useEffect } from 'react';
import {
  Shield, ArrowRight, Play, Cpu, FileCode, CheckCircle2,
  Lock, Scale, BadgeCheck, ShieldCheck, FileText, ArrowDown,
  GitBranch, Scan, Box, Coffee
} from 'lucide-react';
import RedTeamMascot from './RedTeamMascot';
import BlueTeamMascot from './BlueTeamMascot';

function GithubIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"></path>
    </svg>
  );
}

function ChipIcon({ size = 14, className = "" }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <rect x="8.5" y="8.5" width="7" height="7" rx="1" />
      <line x1="8" y1="1" x2="8" y2="4" />
      <line x1="12" y1="1" x2="12" y2="4" />
      <line x1="16" y1="1" x2="16" y2="4" />
      <line x1="8" y1="20" x2="8" y2="23" />
      <line x1="12" y1="20" x2="12" y2="23" />
      <line x1="16" y1="20" x2="16" y2="23" />
      <line x1="1" y1="8" x2="4" y2="8" />
      <line x1="1" y1="12" x2="4" y2="12" />
      <line x1="1" y1="16" x2="4" y2="16" />
      <line x1="20" y1="8" x2="23" y2="8" />
      <line x1="20" y1="12" x2="23" y2="12" />
      <line x1="20" y1="16" x2="23" y2="16" />
    </svg>
  );
}

export default function LandingPage({ setCurrentView }) {
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-revealed');
          }
        });
      },
      {
        threshold: 0.08,
        rootMargin: '0px 0px -40px 0px'
      }
    );

    const elements = document.querySelectorAll('.scroll-reveal');
    elements.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
  }, []);

  return (
    <main className="landing-content" role="main">
      <div className="hero-proof-unified-wrapper">
        <div className="hero-dots-grid-pattern" aria-hidden="true" />

        {/* Hero Section */}
        <section className="hero-editorial-section" aria-label="Hero Section">
          <div className="hero-monster-container">
            <h1 className="hero-monster-title font-oxanium">
              Automate vulnerability remediation from discovery to verification.
            </h1>
            <p className="hero-tagline-orange font-onest">
              Security improvements should come with evidence.
            </p>

            <p className="hero-subtext-muted font-onest">
              Our Red Team discovers and reproduces security flaws while our Blue Team generates patches that undergo independent verification.
            </p>

            {/* CTAs */}
            <div className="hero-monster-actions">
              <button
                onClick={(e) => setCurrentView('arena', e)}
                className="btn-monster-primary font-onest"
                id="hero-start-arena-btn"
              >
                <span>START THE ARENA</span>
                <span className="btn-arrow-right">&rarr;</span>
              </button>

              <a
                href="https://www.youtube.com/watch?v=HxqflEuunmw"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-monster-ghost font-onest"
                id="hero-view-demo-btn"
                style={{ textDecoration: 'none' }}
                aria-label="Watch Demo on YouTube"
              >
                <Play size={13} fill="currentColor" />
                <span>Watch Demo</span>
              </a>
            </div>
          </div>
        </section>

        {/* Independent Verification Workspace */}
        <section className="proof-promises-section scroll-reveal" id="proof-not-promises" aria-label="Independent Verification Workspace">
          <div className="section-container">
            {/* macOS Styled Window Container */}
            <div className="macos-window-frame">
              {/* macOS Window Titlebar */}
              <div className="macos-titlebar">
                <div className="macos-traffic-lights" aria-hidden="true">
                  <span className="traffic-dot dot-close"></span>
                  <span className="traffic-dot dot-minimize"></span>
                  <span className="traffic-dot dot-zoom"></span>
                </div>

                <div className="macos-window-tab-group">
                  <div className="macos-tab active">
                    <FileCode size={13} className="macos-tab-icon" aria-hidden="true" />
                    <span className="macos-tab-name monospace">users.py</span>
                    <span className="macos-diff-stat monospace">
                      <span className="stat-add">+2</span>
                      <span className="stat-del">-2</span>
                    </span>
                  </div>
                </div>

                <div className="macos-window-title monospace">
                  <span>zeroday-oracle // eval_runtime: dry-run sandbox</span>
                </div>
              </div>

              {/* Split Window Body: Code Diff (Left ~58%) + Security Inspector (Right ~42%) */}
              <div className="macos-window-body">
                {/* Left Pane: Code Review & Diff */}
                <div className="macos-code-pane">
                  <div className="pane-sub-header">
                    <div className="pane-breadcrumb monospace">
                      <span className="bc-dim">target_app</span>
                      <span className="bc-sep">/</span>
                      <span className="bc-file">users.py</span>
                    </div>
                  </div>

                  <div className="proof-code-viewport">
                    <div className="diff-line-row diff-context">
                      <span className="diff-lineno monospace">14</span>
                      <span className="diff-gutter monospace"> </span>
                      <span className="diff-text monospace"><span className="kw-def">def</span> <span className="kw-fn">get_user_profile</span>(user_id: <span className="kw-type">str</span>):</span>
                    </div>
                    <div className="diff-line-row diff-context">
                      <span className="diff-lineno monospace">15</span>
                      <span className="diff-gutter monospace"> </span>
                      <span className="diff-text monospace">    cursor = db.cursor()</span>
                    </div>
                    <div className="diff-line-row diff-context">
                      <span className="diff-lineno monospace">16</span>
                      <span className="diff-gutter monospace"> </span>
                      <span className="diff-text monospace comment">    <span className="kw-comment"># Vulnerable raw string interpolation</span></span>
                    </div>
                    <div className="diff-line-row diff-removed">
                      <span className="diff-lineno monospace">17</span>
                      <span className="diff-gutter monospace">-</span>
                      <span className="diff-text monospace">    query = <span className="str-vulnerable">{"f\"SELECT id, name, role FROM users WHERE user_id = '{user_id}'\""}</span></span>
                    </div>
                    <div className="diff-line-row diff-removed">
                      <span className="diff-lineno monospace">18</span>
                      <span className="diff-gutter monospace">-</span>
                      <span className="diff-text monospace">    cursor.execute(query)</span>
                    </div>
                    <div className="diff-line-row diff-added">
                      <span className="diff-lineno monospace">17</span>
                      <span className="diff-gutter monospace">+</span>
                      <span className="diff-text monospace">    query = <span className="str-secure">{'"SELECT id, name, role FROM users WHERE user_id = ?"'}</span></span>
                    </div>
                    <div className="diff-line-row diff-added">
                      <span className="diff-lineno monospace">18</span>
                      <span className="diff-gutter monospace">+</span>
                      <span className="diff-text monospace">    cursor.execute(query, (user_id,))</span>
                    </div>
                    <div className="diff-line-row diff-context">
                      <span className="diff-lineno monospace">19</span>
                      <span className="diff-gutter monospace"> </span>
                      <span className="diff-text monospace">    <span className="kw-def">return</span> cursor.fetchone()</span>
                    </div>
                  </div>

                  <div className="pane-code-footer monospace">
                    <span className="footer-branch">branch: <code>patch-sqli-01</code></span>
                    <span className="footer-status">AST Sink Cleared (CWE-89)</span>
                  </div>
                </div>

                {/* Right Pane: Technical Security Inspector */}
                <div className="macos-inspector-pane">
                  <div className="pane-sub-header">
                    <div className="inspector-header-left">
                      <span className="inspector-title font-oxanium">INSPECTION ORACLE</span>
                    </div>
                  </div>

                  <div className="inspector-entries-container">
                    {/* Entry 1: Security Regression */}
                    <div className="oracle-entry-item">
                      <div className="entry-title-bar">
                        <div className="entry-label-group">
                          <ShieldCheck size={14} className="icon-sage" aria-hidden="true" />
                          <span className="entry-heading font-oxanium">Security Exploit Regression</span>
                        </div>
                      </div>

                      <div className="oracle-terminal-box monospace">
                        <div className="term-row">
                          <span className="term-k">Target:</span>
                          <span className="term-v">POST /api/users/profile</span>
                        </div>
                        <div className="term-row">
                          <span className="term-k">Payload:</span>
                          <span className="term-v payload-text">{"USR-101' OR '1'='1"}</span>
                        </div>
                        <div className="term-row">
                          <span className="term-k">Verdict:</span>
                          <span className="term-v-sage">HTTP 400 Bad Request • 0 rows leaked</span>
                        </div>
                      </div>
                    </div>

                    {/* Entry 2: Functional Invariant Regression */}
                    <div className="oracle-entry-item">
                      <div className="entry-title-bar">
                        <div className="entry-label-group">
                          <CheckCircle2 size={14} className="icon-sage" aria-hidden="true" />
                          <span className="entry-heading font-oxanium">Functional Regression Suite</span>
                        </div>
                      </div>

                      <div className="oracle-terminal-box monospace">
                        <div className="term-row">
                          <span className="term-k">Runner:</span>
                          <span className="term-v">pytest tests/test_users.py -q</span>
                        </div>
                        <div className="term-row">
                          <span className="term-k">Status:</span>
                          <span className="term-v-sage">4 passed in 0.14s (0 regressions)</span>
                        </div>
                        <div className="term-row">
                          <span className="term-k">Contract:</span>
                          <span className="term-v">UserProfile schema contract invariant</span>
                        </div>
                      </div>
                    </div>

                    {/* Entry 3: Cryptographic Verification Seal */}
                    <div className="oracle-entry-item">
                      <div className="entry-title-bar">
                        <div className="entry-label-group">
                          <FileText size={14} className="icon-blue" aria-hidden="true" />
                          <span className="entry-heading font-oxanium">Cryptographic Audit Seal</span>
                        </div>
                      </div>

                      <div className="oracle-terminal-box monospace">
                        <div className="term-row">
                          <span className="term-k">Diff Hash:</span>
                          <span className="term-v">sha256:7f2a1b94e019...3b8a</span>
                        </div>
                        <div className="term-row">
                          <span className="term-k">Isolation:</span>
                          <span className="term-v">Sandboxed ephemeral container (RO)</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="inspector-footer-bar monospace">
                    <span className="inspector-audit-tag">
                      <Lock size={12} className="inline-lock" aria-hidden="true" />
                      Dual-gate certified • Illustrative evaluation model
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>

      {/* Red & Blue Team Agents */}
      <section className="the-arena-section scroll-reveal" id="the-arena" aria-labelledby="the-arena-heading">
        <div className="section-container">
          {/* Section Header */}
          <div className="arena-section-header">
            <h2 className="arena-section-title font-oxanium" id="the-arena-heading">
              THE ARENA
            </h2>
            <p className="arena-section-subtitle font-onest">
              Introducing the Red and Blue Agent
            </p>
          </div>

          <div className="arena-agents-dual-grid">
            {/* Left: Red Team Agent */}
            <div className="arena-agent-column scroll-reveal stagger-1" id="red-team-agent-col">
              <div className="arena-agent-mascot-box">
                <RedTeamMascot size={80} />
              </div>
              <h3 className="arena-agent-title red-agent-title font-oxanium" id="red-agent-heading">
                RED TEAM AGENT
              </h3>
              <p className="arena-agent-description font-onest">
                The Red Team Agent autonomously probes application source code using AST analysis to discover injection flaws and query sinks, generates targeted exploit payloads, and validates zero-day vulnerabilities inside isolated runtime sandboxes.
              </p>
            </div>

            {/* Middle: v/s */}
            <div className="arena-vs-divider font-oxanium" aria-hidden="true">
              <span>v/s</span>
            </div>

            {/* Right: Blue Team Agent */}
            <div className="arena-agent-column scroll-reveal stagger-2" id="blue-team-agent-col">
              <div className="arena-agent-mascot-box">
                <BlueTeamMascot size={80} />
              </div>
              <h3 className="arena-agent-title blue-agent-title font-oxanium" id="blue-agent-heading">
                BLUE TEAM AGENT
              </h3>
              <p className="arena-agent-description font-onest">
                The Blue Team Agent autonomously synthesizes AST-level security patches to neutralize confirmed vulnerabilities, applies defensive parameterization to vulnerable sinks, and authors verified Git pull requests with zero regression.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* System Architecture */}
      <section className="under-the-hood-section scroll-reveal" id="under-the-hood" aria-labelledby="under-the-hood-heading">
        <div id="architecture" className="anchor-jump-target" aria-hidden="true" />
        <div className="section-container">
          {/* Section Introduction: Editorial Header */}
          <div className="hood-editorial-header">
            <h2 className="hood-title font-oxanium" id="under-the-hood-heading">
              SYSTEM ARCHITECTURE
            </h2>
            <p className="hood-subtitle font-onest">
              Deterministic analysis, isolated execution, AI-assisted remediation, and independent verification working seamlessly together.
            </p>
          </div>

          {/* Architecture Flowchart Diagram */}
          <div className="hood-flowchart-wrapper" aria-label="System Architecture Flowchart">
            {/* Row 1: Repository Ingestion */}
            <div className="flowchart-card node-ingestion scroll-reveal stagger-1">
              <div className="flowchart-icon-box icon-steel">
                <GitBranch size={20} strokeWidth={1.8} />
              </div>
              <div className="flowchart-card-content">
                <h3 className="flowchart-node-title font-oxanium">Repository ingestion</h3>
                <p className="flowchart-node-desc font-onest">Python / FastAPI source code</p>
              </div>
            </div>

            {/* Fork Connector: Ingestion -> AST & Sandbox */}
            <div className="flowchart-connector flowchart-connector-fork" aria-hidden="true">
              <div className="connector-stem-down">
                <span className="flow-dot dot-stem-down"></span>
              </div>
              <div className="connector-fork-bar">
                <span className="flow-dot fork-dot-left"></span>
                <span className="flow-dot fork-dot-right"></span>
                <div className="connector-drop-branch drop-left">
                  <div className="branch-line">
                    <span className="flow-dot branch-dot-left"></span>
                  </div>
                  <ArrowDown size={14} className="flow-arrow" />
                </div>
                <div className="connector-drop-branch drop-right">
                  <div className="branch-line">
                    <span className="flow-dot branch-dot-right"></span>
                  </div>
                  <ArrowDown size={14} className="flow-arrow" />
                </div>
              </div>
            </div>

            {/* Row 2: Dual Parallel Nodes (AST + threat intel & Sandbox) */}
            <div className="flowchart-dual-row">
              <div className="flowchart-card node-analysis scroll-reveal stagger-2">
                <div className="flowchart-icon-box icon-crimson">
                  <Scan size={20} strokeWidth={1.8} />
                </div>
                <div className="flowchart-card-content">
                  <h3 className="flowchart-node-title font-oxanium">AST + threat intel</h3>
                  <p className="flowchart-node-desc font-onest">
                    Identify candidate weaknesses and gather supporting context.
                  </p>
                </div>
              </div>

              <div className="flowchart-card node-sandbox scroll-reveal stagger-2">
                <div className="flowchart-icon-box icon-blue">
                  <Box size={20} strokeWidth={1.8} />
                </div>
                <div className="flowchart-card-content">
                  <h3 className="flowchart-node-title font-oxanium">Sandbox</h3>
                  <p className="flowchart-node-desc font-onest">
                    Execute controlled tests against an isolated target.
                  </p>
                </div>
              </div>
            </div>

            {/* Converge Connector: Dual -> Nemotron */}
            <div className="flowchart-connector flowchart-connector-converge" aria-hidden="true">
              <div className="connector-converge-bar">
                <div className="converge-stem-left">
                  <span className="flow-dot converge-stem-dot-left"></span>
                </div>
                <div className="converge-stem-right">
                  <span className="flow-dot converge-stem-dot-right"></span>
                </div>
                <span className="flow-dot converge-dot-left"></span>
                <span className="flow-dot converge-dot-right"></span>
              </div>
              <div className="connector-stem-drop">
                <div className="drop-line">
                  <span className="flow-dot drop-line-dot"></span>
                </div>
                <ArrowDown size={14} className="flow-arrow" />
              </div>
            </div>

            {/* Row 3: Nemotron-assisted Patch Generation */}
            <div className="flowchart-card node-remediation scroll-reveal stagger-3">
              <div className="flowchart-icon-box icon-steel">
                <Cpu size={20} strokeWidth={1.8} />
              </div>
              <div className="flowchart-card-content">
                <h3 className="flowchart-node-title font-oxanium">Nemotron-assisted patch generation</h3>
                <p className="flowchart-node-desc font-onest">
                  Generate a candidate remediation through Nebius Token Factory.
                </p>
              </div>
            </div>

            {/* Direct Connector: Nemotron -> Verification */}
            <div className="flowchart-connector flowchart-connector-direct" aria-hidden="true">
              <div className="connector-direct-line">
                <span className="flow-dot direct-line-dot"></span>
              </div>
              <ArrowDown size={14} className="flow-arrow" />
            </div>

            {/* Row 4: Independent Verification */}
            <div className="flowchart-card node-verification scroll-reveal stagger-4">
              <div className="flowchart-icon-box icon-sage">
                <ShieldCheck size={20} strokeWidth={1.8} />
              </div>
              <div className="flowchart-card-content">
                <h3 className="flowchart-node-title font-oxanium">Independent verification</h3>
                <p className="flowchart-node-desc font-onest">
                  Security regression checks, functional tests, and evidence reporting.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Remediation Pipeline & Stages */}
      <div className="stages-wordmark-unified-wrapper">
        {/* Subtle engineering dot matrix backdrop matching Hero */}
        <div className="stages-dots-grid-pattern" aria-hidden="true" />

        {/* 5. STAGES FROM FIRST SCAN TO VERIFIED FIX (6 Stages) */}
        <section className="stages-pipeline-section scroll-reveal" id="how-it-works" aria-labelledby="stages-pipeline-heading">
          <div className="section-container">
            <div className="stages-section-header">
              <h2 className="stages-section-title font-oxanium" id="stages-pipeline-heading">
                STAGES FROM FIRST SCAN TO VERIFIED FIX
              </h2>
            </div>

            <div className="stages-six-grid">
              {/* 1: RECONNAISSANCE */}
              <div className="stage-item scroll-reveal stagger-1">
                <span className="stage-num font-oxanium">1</span>
                <div className="stage-icon-wrap" aria-hidden="true">
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="7 8 3 12 7 16" />
                    <polyline points="17 8 21 12 17 16" />
                    <line x1="14" y1="4" x2="10" y2="20" />
                  </svg>
                </div>
                <h3 className="stage-title font-oxanium">
                  RECONNAISSANCE
                </h3>
                <p className="stage-desc font-onest">
                  AST analysis maps routes and endpoints without execution.
                </p>
              </div>

              {/* 2: THREAT GROUNDING */}
              <div className="stage-item scroll-reveal stagger-2">
                <span className="stage-num font-oxanium">2</span>
                <div className="stage-icon-wrap" aria-hidden="true">
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="2" />
                    <path d="M16.24 7.76a6 6 0 1 0 0 8.49" />
                    <path d="M19.07 4.93a10 10 0 1 0 0 14.14" />
                    <line x1="12" y1="12" x2="19" y2="5" />
                  </svg>
                </div>
                <h3 className="stage-title font-oxanium">
                  THREAT<br />GROUNDING
                </h3>
                <p className="stage-desc font-onest">
                  Tavily Search queries fresh CVEs and OWASP guides.
                </p>
              </div>

              {/* 3: ADVERSARIAL EXPLOITATION */}
              <div className="stage-item scroll-reveal stagger-3">
                <span className="stage-num font-oxanium">3</span>
                <div className="stage-icon-wrap" aria-hidden="true">
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="9" />
                  </svg>
                </div>
                <h3 className="stage-title font-oxanium">
                  ADVERSARIAL<br />EXPLOITATION
                </h3>
                <p className="stage-desc font-onest">
                  Synthesizes and executes runtime HTTP payloads.
                </p>
              </div>

              {/* 4: BREACH TRIAGE */}
              <div className="stage-item scroll-reveal stagger-4">
                <span className="stage-num font-oxanium">4</span>
                <div className="stage-icon-wrap" aria-hidden="true">
                  <Scale size={28} strokeWidth={1.6} />
                </div>
                <h3 className="stage-title font-oxanium">
                  BREACH TRIAGE
                </h3>
                <p className="stage-desc font-onest">
                  Nemotron Nano isolates lines and routes to coder tiers.
                </p>
              </div>

              {/* 5: SECURE PATCHING */}
              <div className="stage-item scroll-reveal stagger-5">
                <span className="stage-num font-oxanium">5</span>
                <div className="stage-icon-wrap" aria-hidden="true">
                  <Shield size={28} strokeWidth={1.6} />
                </div>
                <h3 className="stage-title font-oxanium">
                  SECURE<br />PATCHING
                </h3>
                <p className="stage-desc font-onest">
                  Frontier model drafts a strict, type-safe Git diff.
                </p>
              </div>

              {/* 6: DETERMINISTIC VERIFICATION */}
              <div className="stage-item scroll-reveal stagger-6">
                <span className="stage-num font-oxanium">6</span>
                <div className="stage-icon-wrap" aria-hidden="true">
                  <BadgeCheck size={28} strokeWidth={1.6} />
                </div>
                <h3 className="stage-title font-oxanium">
                  DETERMINISTIC<br />VERIFICATION
                </h3>
                <p className="stage-desc font-onest">
                  Deterministic dual-gate testing confirms neutralization.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* OVERSIZED ZERODAY WORDMARK SECTION */}
        <section className="oversized-wordmark-section" aria-label="Brand Signature">
          <div className="oversized-wordmark-container">
            <span className="oversized-wordmark-text font-oxanium">ZERODAY</span>
          </div>
        </section>
      </div>

      {/* SITE FOOTER */}
      <footer className="app-footer" role="contentinfo">
        <div className="footer-container">
          {/* Main Editorial Grid: Left Brand & Hackathon Pill / Right Platform & Tech Stack */}
          <div className="footer-editorial-grid">
            {/* Left Column: ZERODAY Brand + Badge Pill + Description */}
            <div className="footer-left-brand-block">
              <div className="footer-brand-header-row">
                <span className="footer-zeroday-logo font-oxanium">ZERODAY</span>
                <div className="footer-hackathon-pill" aria-label="Nebius x NVIDIA Global AI Hackathon 2026">
                  <ChipIcon size={14} className="badge-chip-icon" />
                  <span className="brand-nebius font-oxanium">NEBIUS</span>
                  <span className="brand-x font-oxanium">x</span>
                  <span className="brand-nvidia font-oxanium">NVIDIA</span>
                  <span className="brand-event font-oxanium">GLOBAL AI HACKATHON 2026</span>
                </div>
              </div>

              <p className="footer-zeroday-desc font-onest">
                Autonomous, self-healing cybersecurity infrastructure that finds vulnerabilities, verifies exploits in isolated sandboxes, and authors verified patches with zero human lag.
              </p>
            </div>

            {/* Right Columns: Platform & Technology Stack */}
            <div className="footer-right-nav-block">
              {/* Platform Column */}
              <div className="footer-nav-col">
                <h4 className="footer-nav-heading monospace">Platform:</h4>
                <ul className="footer-nav-list font-onest">
                  <li>
                    <a
                      href="/benchmarks"
                      onClick={(e) => {
                        e.preventDefault();
                        if (typeof setCurrentView === 'function') {
                          setCurrentView('benchmarks', e);
                        } else {
                          window.location.href = '/benchmarks';
                        }
                      }}
                      className="footer-nav-link link-platform"
                    >
                      Benchmarks
                    </a>
                  </li>
                  <li>
                    <a
                      href="/documentation"
                      onClick={(e) => {
                        e.preventDefault();
                        if (typeof setCurrentView === 'function') {
                          setCurrentView('documentation', e);
                        } else {
                          window.location.href = '/documentation';
                        }
                      }}
                      className="footer-nav-link link-platform"
                    >
                      Documentation
                    </a>
                  </li>
                  <li>
                    <a
                      href="/hackathon"
                      onClick={(e) => {
                        e.preventDefault();
                        if (typeof setCurrentView === 'function') {
                          setCurrentView('hackathon', e);
                        } else {
                          window.location.href = '/hackathon';
                        }
                      }}
                      className="footer-nav-link link-platform"
                    >
                      Hackathon Project
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://github.com/darshansahare"
                      target="_blank"
                      rel="noreferrer"
                      className="footer-nav-link link-platform link-github"
                    >
                      <GithubIcon size={14} />
                      <span>Github</span>
                    </a>
                  </li>
                </ul>
              </div>

              {/* Technology Stack Column */}
              <div className="footer-nav-col">
                <h4 className="footer-nav-heading monospace">Technology Stack:</h4>
                <ul className="footer-nav-list font-onest">
                  <li>
                    <a
                      href="https://tokenfactory.nebius.com"
                      target="_blank"
                      rel="noreferrer"
                      className="footer-nav-link link-nebius"
                    >
                      Nebius Token Factory
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://catalog.ngc.nvidia.com"
                      target="_blank"
                      rel="noreferrer"
                      className="footer-nav-link link-nvidia"
                    >
                      NVIDIA Nemotron
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://tavily.com"
                      target="_blank"
                      rel="noreferrer"
                      className="footer-nav-link link-tavily"
                    >
                      Tavily
                    </a>
                  </li>
                </ul>
              </div>
            </div>
          </div>

          {/* Divider Below */}
          <div className="footer-divider-bar" aria-hidden="true" />

          {/* Bottom Bar: Copyright MIT License on Left, Coffee Quote on Right */}
          <div className="footer-bottom-deck font-onest">
            <div className="footer-bottom-left">
              <span>&copy; 2026 ZeroDay Arena. MIT License.</span>
            </div>

            <div className="footer-bottom-right">
              <Coffee size={14} className="footer-coffee-icon" aria-hidden="true" />
              <span className="footer-coffee-text">
                A little Nemotron, a lot of determination, and way too much coffee.
              </span>
            </div>
          </div>
        </div>
      </footer>

    </main>
  );
}
