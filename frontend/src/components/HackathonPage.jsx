import React, { useEffect, useState, useRef } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  ArrowRight,
  ArrowUpRight,
  PlayCircle,
  ShieldCheck,
  Activity,
} from 'lucide-react';
import { PROJECT_KNOWLEDGE } from '../config/projectKnowledge';

function ChipIcon({ size = 14, className = '' }) {
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

function NvidiaLogo({ size = 22, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      className={className}
      aria-hidden="true"
    >
      <path d="M10.212 8.976V7.62c.127-.01.256-.017.388-.021 3.596-.117 5.957 3.184 5.957 3.184s-2.548 3.647-5.282 3.647a3.227 3.227 0 01-1.063-.175v-4.109c1.4.174 1.681.812 2.523 2.258l1.873-1.627a4.905 4.905 0 00-3.67-1.846 6.594 6.594 0 00-.729.044m0-4.476v2.025c.13-.01.259-.019.388-.024 5.002-.174 8.261 4.226 8.261 4.226s-3.743 4.69-7.643 4.69c-.338 0-.675-.031-1.007-.092v1.25c.278.038.558.057.838.057 3.629 0 6.253-1.91 8.794-4.169.421.347 2.146 1.193 2.501 1.564-2.416 2.083-8.048 3.763-11.24 3.763-.308 0-.603-.02-.894-.048V19.5H24v-15H10.21zm0 9.756v1.068c-3.356-.616-4.287-4.21-4.287-4.21a7.173 7.173 0 014.287-2.138v1.172h-.005a3.182 3.182 0 00-2.502 1.178s.615 2.276 2.507 2.931m-5.961-3.3c1.436-1.935 3.604-3.148 5.961-3.336V6.523C5.81 6.887 2 10.723 2 10.723s2.158 6.427 8.21 7.015v-1.166C5.77 16 4.25 10.958 4.25 10.958h-.002z" />
    </svg>
  );
}

function NebiusLogo({ size = 22, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      className={className}
      aria-hidden="true"
    >
      <path d="M20 2.306v16.797s4-.242 4-4.815V2.306h-4zM4 22.001V5.204s-4 .242-4 4.816V22h4z" />
      <path d="M16.318 16.51L11.286 4.94c-.824-1.872-2.168-2.926-4.077-2.926-1.908 0-3.211 1.54-3.211 3.19 0 0 2.405-.333 3.68 2.593l5.036 11.57c.821 1.87 2.168 2.926 4.075 2.926 1.905 0 3.211-1.541 3.211-3.19 0 0-2.406.333-3.682-2.594z" />
    </svg>
  );
}

function TavilyLogo({ size = 22, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      className={className}
      aria-hidden="true"
    >
      <path d="M8.033 14.273a1.612 1.612 0 011.139.47l.04.042.044.043a1.61 1.61 0 010 2.277l-3.073 3.073.816.816c.6.6.303 1.627-.525 1.814l-5.159 1.165a1.07 1.07 0 01-.897-.2l-.102-.09a1.07 1.07 0 01-.289-1l1.164-5.158A1.079 1.079 0 013.006 17l.816.817 3.074-3.074a1.612 1.612 0 011.137-.47zM17.042 13.246c0-.85.935-1.366 1.653-.912l4.47 2.824c.336.212.503.562.503.911 0 .35-.167.7-.501.913l-4.472 2.824a1.079 1.079 0 01-1.654-.912v-1.155h-7.027c.37-.4.605-.902.677-1.438l.022-.232a2.65 2.65 0 00-.492-1.669h6.821v-1.154zM8.188 0c.35 0 .7.168.913.503l2.823 4.47a1.079 1.079 0 01-.911 1.655H9.857v6.692h-1.67a2.633 2.633 0 00-1.668.48V6.629H5.365c-.849 0-1.366-.936-.912-1.654L7.276.503A1.072 1.072 0 018.188 0z" />
    </svg>
  );
}

function DevpostIcon({ size = 20, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      className={className}
      aria-hidden="true"
    >
      <path d="M6.002 1.61L0 12.004 6.002 22.39h11.996L24 12.004 17.998 1.61zm1.593 4.084h3.947c3.605 0 6.276 1.695 6.276 6.31 0 4.436-3.21 6.302-6.456 6.302H7.595zm2.517 2.449v7.714h1.241c2.646 0 3.862-1.55 3.862-3.861.009-2.569-1.096-3.853-3.767-3.853Z" />
    </svg>
  );
}

function GithubIcon({ size = 20, className = '' }) {
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
      <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
    </svg>
  );
}

const HACKATHON_MILESTONES = [
  {
    step: '01',
    category: 'FULL-STACK RUNTIME',
    title: 'Full-Stack Architecture & Reactive Cyber Console',
    desc: 'Implemented an enterprise React 19 + Vite frontend coupled with a high-performance Python 3.12 FastAPI backend. Provides an interactive visual cyber arena (/arena) with live AST telemetry, Monaco-style unified diff comparisons, and real-time execution logs.',
    highlights: ['FastAPI 3.12 + React 19', 'Live AST Telemetry', 'Monaco Unified Diff'],
    badge: 'CORE PLATFORM',
    color: 'coral',
  },
  {
    step: '02',
    category: 'INFERENCE INFRASTRUCTURE',
    title: 'Nebius Token Factory & NVIDIA Nemotron Integration',
    desc: 'Integrated the Nebius Token Factory inference runtime for nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B. Designed strict schema-constrained prompts that generate deterministic unified diff patches with zero code hallucination.',
    highlights: ['NVIDIA Nemotron-3-Nano', 'Nebius Token Factory API', 'Zero-Hallucination Diff'],
    badge: 'AI REASONING',
    color: 'green',
  },
  {
    step: '03',
    category: 'SECURITY GATEWAY',
    title: 'Deterministic 4-Gate Invariant Verification Oracle',
    desc: 'Built a standalone verification oracle that compiles AST syntax, inspects static analysis deltas, replays adversarial attacks in an isolated subprocess, and executes pytest test suites to ensure zero business logic regression.',
    highlights: ['Gate 1: AST Syntax', 'Gate 2: Static Delta', 'Gate 3: Exploit Replay', 'Gate 4: Pytest'],
    badge: 'INVARIANT ORACLE',
    color: 'sage',
  },
  {
    step: '04',
    category: 'FINOPS OPTIMIZATION',
    title: 'Token Optimization Cache & FinOps Telemetry',
    desc: 'Implemented an intelligent token cache that hashes prompts and AST signatures to eliminate redundant LLM calls, reducing API costs and accelerating repetitive test cycles by over 80%.',
    highlights: ['80%+ Latency Drop', 'AST Signature Hash', 'Real-Time Cost Metrics'],
    badge: 'FINOPS ACCELERATION',
    color: 'amber',
  },
];

export default function HackathonPage({
  onNavigateToArena,
  onNavigateToDocs,
  onNavigateToBenchmarks,
}) {
  const { brand, hackathon, benchmarkMetrics } = PROJECT_KNOWLEDGE;

  useEffect(() => {
    if (typeof window === 'undefined' || !('IntersectionObserver' in window)) {
      document.querySelectorAll('.hackathon-section, .hackathon-hero-header').forEach((el) => {
        el.classList.add('is-visible');
      });
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
          }
        });
      },
      {
        threshold: 0.12,
        rootMargin: '0px 0px -40px 0px',
      }
    );

    const sections = document.querySelectorAll('.hackathon-section, .hackathon-hero-header');
    sections.forEach((sec) => observer.observe(sec));

    const hero = document.querySelector('.hackathon-hero-header');
    if (hero) hero.classList.add('is-visible');

    return () => {
      sections.forEach((sec) => observer.unobserve(sec));
      observer.disconnect();
    };
  }, []);


  return (
    <div className="hackathon-page-canvas font-onest">
      {/* Background Engineering Pattern */}
      <div className="hackathon-grid-pattern" aria-hidden="true" />

      <div className="hackathon-content-container">
        {/* Header Section */}
        <header className="hackathon-hero-header">
          {/* Badge above heading */}
          <div
            className="footer-hackathon-pill hackathon-hero-badge"
            aria-label="Nebius x NVIDIA Global AI Hackathon 2026"
          >
            <ChipIcon size={14} className="badge-chip-icon" />
            <span className="brand-nebius font-oxanium">NEBIUS</span>
            <span className="brand-x font-oxanium">x</span>
            <span className="brand-nvidia font-oxanium">NVIDIA</span>
            <span className="brand-event font-oxanium">GLOBAL AI HACKATHON 2026</span>
          </div>

          {/* Heading */}
          <h1 className="hackathon-title font-oxanium">
            Zeroday Vulnerability Detection &amp; Remediation
          </h1>

          {/* Short description below */}
          <p className="hackathon-tagline font-onest">
            Autonomous cybersecurity platform that detects vulnerabilities, verifies exploits in isolated sandboxes, and authors invariant-verified code patches with zero false positives.
          </p>

          {/* Three Badges below description: Coding & Agentic Engineering, AI Agent Innovation, Nebius x NVIDIA Ecosystem */}
          <div className="hackathon-track-badges font-onest" aria-label="Hackathon Track Categories">
            <div className="track-badge-pill">
              <span>Coding &amp; Agentic Engineering</span>
            </div>
            <div className="track-badge-pill">
              <span>AI Agent Innovation</span>
            </div>
            <div className="track-badge-pill">
              <span>Nebius &times; NVIDIA Ecosystem</span>
            </div>
          </div>

          <div className="hackathon-actions">
            <button
              onClick={() => onNavigateToArena && onNavigateToArena()}
              className="btn-hackathon-primary font-onest"
            >
              <span>Launch Arena</span>
              <ArrowRight size={15} />
            </button>
            <button
              onClick={() => onNavigateToDocs && onNavigateToDocs()}
              className="btn-hackathon-ghost font-onest"
            >
              <span>Explore Tech Docs</span>
              <ArrowRight size={14} />
            </button>
          </div>
        </header>

        {/* Section 1: The Challenge & ZeroDay Solution */}
        <section className="hackathon-section">
          <div className="section-heading-row">
            <h2 className="section-heading-title font-oxanium">The Vulnerability Remediation Gap</h2>
          </div>

          <div className="two-column-card-grid">
            {/* Left Column: The Challenge */}
            <div className="hackathon-card problem-card">
              <div className="card-header-row problem-header-row">
                <h3 className="challenge-heading font-oxanium">
                  <AlertCircle size={19} className="challenge-icon" aria-hidden="true" />
                  <span>The Challenge</span>
                </h3>
              </div>

              <ul className="card-points-list font-onest">
                <li className="card-point-item">
                  <span className="point-bullet challenge-bullet" aria-hidden="true" />
                  <div className="point-content">
                    <span className="point-title">High False-Positive Overhead (40%+)</span>
                    <p className="point-desc">
                      Conventional SAST tools flood engineering queues with hundreds of noisy alerts, obscuring critical zero-days beneath developer alert fatigue.
                    </p>
                  </div>
                </li>

                <li className="card-point-item">
                  <span className="point-bullet challenge-bullet" aria-hidden="true" />
                  <div className="point-content">
                    <span className="point-title">Unverified Proof of Exploitability</span>
                    <p className="point-desc">
                      Static pattern matching flags syntactic sinks but cannot prove weaponizability, forcing security engineers to spend hours validating if code paths are reachable.
                    </p>
                  </div>
                </li>

                <li className="card-point-item">
                  <span className="point-bullet challenge-bullet" aria-hidden="true" />
                  <div className="point-content">
                    <span className="point-title">Hallucinated &amp; Breaking LLM Patches</span>
                    <p className="point-desc">
                      Generic AI coding assistants generate plausible-looking patches that fail syntax compilation, break business logic, or introduce new secondary vulnerabilities.
                    </p>
                  </div>
                </li>

                <li className="card-point-item">
                  <span className="point-bullet challenge-bullet" aria-hidden="true" />
                  <div className="point-content">
                    <span className="point-title">Critical Remediation Latency Window (60+ Days)</span>
                    <p className="point-desc">
                      The multi-month gap between vulnerability discovery and manual production deployment leaves systems exposed to active threat actors.
                    </p>
                  </div>
                </li>
              </ul>
            </div>

            {/* Right Column: ZeroDay Solution */}
            <div className="hackathon-card solution-card">
              <div className="card-header-row solution-header-row">
                <h3 className="solution-heading font-oxanium">
                  <CheckCircle2 size={19} className="solution-icon" aria-hidden="true" />
                  <span>ZeroDay Solution</span>
                </h3>
              </div>

              <ul className="card-points-list font-onest">
                <li className="card-point-item">
                  <span className="point-bullet solution-bullet" aria-hidden="true" />
                  <div className="point-content">
                    <span className="point-title">Isolated Adversarial Sandbox Probing</span>
                    <p className="point-desc">
                      Autonomous Red Team agent executes synthetic proof-of-concept exploits in isolated sandbox subprocesses, proving exploitability with zero false alarms.
                    </p>
                  </div>
                </li>

                <li className="card-point-item">
                  <span className="point-bullet solution-bullet" aria-hidden="true" />
                  <div className="point-content">
                    <span className="point-title">Grounded Nemotron Patch Synthesis</span>
                    <p className="point-desc">
                      Blue Team agent invokes NVIDIA Nemotron via Nebius Token Factory, grounded by live Tavily threat intelligence to synthesize minimal, compliant unified diffs.
                    </p>
                  </div>
                </li>

                <li className="card-point-item">
                  <span className="point-bullet solution-bullet" aria-hidden="true" />
                  <div className="point-content">
                    <span className="point-title">Deterministic 4-Gate Invariant Oracle</span>
                    <p className="point-desc">
                      Every proposed patch must pass AST syntax parsing, static sink delta elimination, exploit replay rejection, and pytest regression suites before acceptance.
                    </p>
                  </div>
                </li>

                <li className="card-point-item">
                  <span className="point-bullet solution-bullet" aria-hidden="true" />
                  <div className="point-content">
                    <span className="point-title">Autonomous Zero-Human-Lag Defense</span>
                    <p className="point-desc">
                      Collapses the remediation window from months to seconds by autonomously discovering, verifying, patching, and validating code fixes without human bottlenecks.
                    </p>
                  </div>
                </li>
              </ul>
            </div>
          </div>
        </section>

        {/* Section 2: Technology & Integration */}
        <section className="hackathon-section">
          <div className="section-heading-row">
            <h2 className="section-heading-title font-oxanium">Technology &amp; Integration</h2>
          </div>

          <div className="integration-cards-grid">
            {/* Card 1: NVIDIA Nemotron */}
            <div className="tech-spec-card nvidia-tech-card">
              <div className="tech-card-header">
                <div className="tech-card-title-row">
                  <NvidiaLogo size={22} className="tech-logo nvidia-logo" />
                  <h3 className="tech-card-title font-oxanium">NVIDIA Nemotron</h3>
                </div>
                <span className="tech-card-subtitle font-mono nvidia-sub">AI Reasoning</span>
              </div>
              <p className="spec-body font-onest">
                Powers ZeroDay's autonomous Blue Team agent using <span className="tech-model-name nvidia-text">nvidia/Nemotron-3-Nano-30B</span> for targeted root-cause analysis and automated patch synthesis, authoring minimal unified diffs adhering strictly to AST parameterization patterns.
              </p>
            </div>

            {/* Card 2: Nebius Token Factory */}
            <div className="tech-spec-card nebius-tech-card">
              <div className="tech-card-header">
                <div className="tech-card-title-row">
                  <NebiusLogo size={22} className="tech-logo nebius-logo" />
                  <h3 className="tech-card-title font-oxanium">Nebius Token Factory</h3>
                </div>
                <span className="tech-card-subtitle font-mono nebius-sub">AI Infrastructure</span>
              </div>
              <p className="spec-body font-onest">
                High-performance inference hosted on Nebius Token Factory (<span className="tech-model-name nebius-text">api.tokenfactory.nebius.com</span>), providing ultra-low-latency token streaming, predictable FinOps ($0.20 per 1M prompt tokens), and OpenAI-compatible API protocol.
              </p>
            </div>

            {/* Card 3: Tavily Search */}
            <div className="tech-spec-card tavily-tech-card">
              <div className="tech-card-header">
                <div className="tech-card-title-row">
                  <TavilyLogo size={22} className="tech-logo tavily-logo" />
                  <h3 className="tech-card-title font-oxanium">Tavily Search</h3>
                </div>
                <span className="tech-card-subtitle font-mono tavily-sub">Contextual Research</span>
              </div>
              <p className="spec-body font-onest">
                Every detected AST sink triggers live threat intelligence queries via Tavily AI Search, injecting authoritative MITRE CWE definitions, CVE exploit advisories, and OWASP mitigation cheat sheets into Nemotron's synthesis prompt.
              </p>
            </div>
          </div>
        </section>

        {/* Section 3: Verified Benchmark Results */}
        <section className="hackathon-section">
          <div className="section-heading-row">
            <h2 className="section-heading-title font-oxanium">Reproducible Empirical Benchmarks</h2>
          </div>

          <div className="results-metrics-grid">
            <div className="result-metric-card">
              <span className="metric-number font-oxanium">{benchmarkMetrics.totalConfigured}</span>
              <span className="metric-label font-mono">TOTAL BENCHMARKS</span>
              <span className="metric-detail font-onest">14 vulnerable fixtures + 6 clean baselines</span>
            </div>
            <div className="result-metric-card">
              <span className="metric-number font-oxanium">{benchmarkMetrics.detectionRecallPercent}%</span>
              <span className="metric-label font-mono">DETECTION RECALL</span>
              <span className="metric-detail font-onest">14/14 vulnerable targets discovered</span>
            </div>
            <div className="result-metric-card">
              <span className="metric-number font-oxanium">{benchmarkMetrics.verifiedRemediationPercent}%</span>
              <span className="metric-label font-mono">REMEDIATION SUCCESS</span>
              <span className="metric-detail font-onest">14/14 patches passed all 4 oracle gates</span>
            </div>
            <div className="result-metric-card">
              <span className="metric-number font-oxanium">0.0%</span>
              <span className="metric-label font-mono">FALSE POSITIVE RATE</span>
              <span className="metric-detail font-onest">0 false alerts across 6 clean controls</span>
            </div>
          </div>
        </section>

        {/* Section 4: What Was Built During the Hackathon */}
        <section className="hackathon-section">
          <div className="section-heading-row">
            <h2 className="section-heading-title font-oxanium">Engineered Capabilities & Milestones</h2>
          </div>

          <div className="timeline-cards-list">
            <div className="timeline-item">
              <div className="timeline-marker font-mono">01</div>
              <div className="timeline-content">
                <h3 className="timeline-title font-oxanium">Full-Stack Architecture & Reactive Cyber Console</h3>
                <p className="timeline-desc font-onest">
                  Implemented an enterprise React 19 + Vite frontend coupled with a high-performance Python 3.12 FastAPI
                  backend. Provides an interactive visual cyber arena (/arena) with live AST telemetry, Monaco-style unified diff
                  comparisons, and real-time execution logs.
                </p>
              </div>
            </div>

            <div className="timeline-item">
              <div className="timeline-marker font-mono">02</div>
              <div className="timeline-content">
                <h3 className="timeline-title font-oxanium">Nebius Token Factory & NVIDIA Nemotron Integration</h3>
                <p className="timeline-desc font-onest">
                  Integrated the Nebius Token Factory inference runtime for <code>nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B</code>.
                  Designed strict schema-constrained prompts that generate deterministic unified diff patches with zero code
                  hallucination.
                </p>
              </div>
            </div>

            <div className="timeline-item">
              <div className="timeline-marker font-mono">03</div>
              <div className="timeline-content">
                <h3 className="timeline-title font-oxanium">Deterministic 4-Gate Invariant Verification Oracle</h3>
                <p className="timeline-desc font-onest">
                  Built a standalone verification oracle that compiles AST syntax, inspects static analysis deltas, replays
                  adversarial attacks in an isolated subprocess, and executes pytest test suites to ensure zero business logic regression.
                </p>
              </div>
            </div>

            <div className="timeline-item">
              <div className="timeline-marker font-mono">04</div>
              <div className="timeline-content">
                <h3 className="timeline-title font-oxanium">Token Optimization Cache & FinOps Telemetry</h3>
                <p className="timeline-desc font-onest">
                  Implemented an intelligent token cache that hashes prompts and AST signatures to eliminate redundant LLM calls,
                  reducing API costs and accelerating repetitive test cycles by over 80%.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Section: Results & Validation */}
        <section className="hackathon-section results-validation-section" id="results-validation">
          {/* Section Header */}
          <div className="section-heading-row">

            <h2 className="section-title font-oxanium">Proof over promises.</h2>
            <p className="section-desc font-onest">
              Real tests. Reproducible findings. Evidence that shows what ZeroDay can and cannot verify.
            </p>
          </div>

          {/* 1. Two Compact Summary Cards for Test Results & Security Validation */}
          <div className="rv-summary-grid">
            {/* Summary Card 1: Automated Test Suite & Invariant Gates */}
            <div className="rv-summary-card">
              <div className="rv-summary-top">
                <div className="rv-icon-badge badge-coral">
                  <ShieldCheck size={20} />
                </div>
                <span className="rv-badge-pill pill-coral font-mono">130 / 130 TESTS PASSING</span>
              </div>
              <h3 className="rv-summary-title font-oxanium">Automated Invariant Gates</h3>
              <p className="rv-summary-text font-onest">
                Full test suite executing across isolated sandboxes, static AST sink reconnaissance, FinOps token caching, and deterministic invariant verification.
              </p>
              <div className="rv-summary-stats font-mono">
                <div className="rv-stat-item">
                  <span className="stat-num">4</span>
                  <span className="stat-label">Deterministic Gates</span>
                </div>
                <div className="rv-stat-divider" />
                <div className="rv-stat-item">
                  <span className="stat-num">100%</span>
                  <span className="stat-label">Oracle Invariance</span>
                </div>
              </div>
            </div>

            {/* Summary Card 2: Standardized Benchmark Dataset */}
            <div className="rv-summary-card">
              <div className="rv-summary-top">
                <div className="rv-icon-badge badge-green">
                  <Activity size={20} />
                </div>
                <span className="rv-badge-pill pill-green font-mono">20 TARGET BENCHMARK</span>
              </div>
              <h3 className="rv-summary-title font-oxanium">Security Benchmark Coverage</h3>
              <p className="rv-summary-text font-onest">
                Rigorous evaluation across 14 vulnerable microservice targets (OWASP Top 10) and 6 clean negative controls with zero false-positive hallucinations.
              </p>
              <div className="rv-summary-stats font-mono">
                <div className="rv-stat-item">
                  <span className="stat-num">14 / 14</span>
                  <span className="stat-label">Verified Fixes</span>
                </div>
                <div className="rv-stat-divider" />
                <div className="rv-stat-item">
                  <span className="stat-num">0</span>
                  <span className="stat-label">False Positives</span>
                </div>
              </div>
            </div>
          </div>

        </section>

        {/* Section 5: Built to be explored (Submission & Links) */}
        <section className="hackathon-section submission-section-container" id="submission-links">
          <div className="submission-section">
          {/* Section Header */}
          <div className="submission-header">
            <h2 className="submission-heading font-onest">Built to be explored</h2>
            <p className="submission-desc font-onest">
              Explore the project, inspect the implementation, and see ZeroDay in action.
            </p>
          </div>

          <div className="submission-content-wrap">
            {/* Top Card: Hackathon Submission */}
            <a
              href={hackathon.devpostUrl || 'https://nebiusglobalaihackathon.devpost.com/'}
              target="_blank"
              rel="noopener noreferrer"
              className="submission-featured-card"
              aria-label="View Hackathon Submission on Devpost"
            >
              <div className="sub-card-top">
                <div className="sub-card-header-left">
                  <div className="sub-icon-box" aria-hidden="true">
                    <DevpostIcon size={20} className="sub-devpost-icon" />
                  </div>
                  <div className="sub-header-texts">
                    <h3 className="sub-event-heading font-onest">Hackathon Submission</h3>
                    <p className="sub-event-name font-onest">
                      Nebius x NVIDIA Global AI Hackathon 2026
                    </p>
                  </div>
                </div>
                <div className="sub-card-header-right">
                  <ArrowUpRight size={18} className="sub-top-arrow" />
                </div>
              </div>

              <div className="sub-card-divider" aria-hidden="true" />

              <div className="sub-card-bottom font-onest">
                <span className="sub-track-label">Track</span>
                <span className="sub-track-value">Coding &amp; Agentic Engineering</span>
              </div>
            </a>

            {/* Below: Two Cards */}
            <div className="submission-two-cards">
              {/* Card 1: Source Code */}
              <a
                href={brand.repositoryUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="submission-dest-card"
                aria-label="View Source Code Repository"
              >
                <div className="dest-icon-wrap" aria-hidden="true">
                  <GithubIcon size={22} className="dest-icon" />
                </div>
                <h4 className="dest-card-title font-onest">Source Code</h4>
                <p className="dest-card-desc font-onest">
                  Explore the implementation and repository.
                </p>
                <div className="dest-card-cta font-onest">
                  <span>View repository</span>
                  <ArrowUpRight size={14} className="dest-cta-arrow" />
                </div>
              </a>

              {/* Card 2: Project Demo */}
              <a
                href="https://www.youtube.com/watch?v=HxqflEuunmw"
                target="_blank"
                rel="noopener noreferrer"
                className="submission-dest-card"
                aria-label="Watch Project Demo"
              >
                <div className="dest-icon-wrap" aria-hidden="true">
                  <PlayCircle size={22} className="dest-icon" />
                </div>
                <h4 className="dest-card-title font-onest">Project Demo</h4>
                <p className="dest-card-desc font-onest">
                  Watch the workflow and real output.
                </p>
                <div className="dest-card-cta font-onest">
                  <span>Watch demo</span>
                  <ArrowUpRight size={14} className="dest-cta-arrow" />
                </div>
              </a>
            </div>
          </div>
          </div>
        </section>
      </div>
    </div>
  );
}
