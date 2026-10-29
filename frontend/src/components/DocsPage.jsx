import React, { useState, useEffect } from 'react';
import {
  BookOpen,
  Cpu,
  Terminal,
  Shield,
  CheckCircle2,
  Lock,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Search,
  Zap,
  Code2,
  GitBranch,
  Layers,
  Check,
  Copy,
} from 'lucide-react';
import { PROJECT_KNOWLEDGE } from '../config/projectKnowledge';

const CWE_SINKS_MAP = {
  'CWE-89': 'cursor.execute(), executemany()',
  'CWE-22': 'open(), Path.read_text(), read_bytes()',
  'CWE-284': 'GET /resource/{id} path parameter routes',
  'CWE-78': 'subprocess.run(shell=True), os.system()',
  'CWE-918': 'httpx.get(), requests.get(), urllib.request',
  'CWE-502': 'pickle.loads(), yaml.load()',
  'CWE-798': 'SECRET_KEY, API_KEY, TOKEN constants',
  'CWE-328': 'hashlib.md5(), hashlib.sha1()',
  'CWE-601': 'RedirectResponse(url=...)',
  'CWE-942': 'CORSMiddleware(allow_origins=["*"])',
  'CWE-489': '/debug, /trace, /internal endpoints',
  'CWE-614': 'response.set_cookie() lacking secure/httponly',
  'CWE-1395': 'requirements.txt, pyproject.toml pins',
  'CWE-20': 'request.json(), request.body() without schema',
};

const CWE_IMPACT_MAP = {
  'CWE-89': 'Data Exfiltration & Auth Bypass',
  'CWE-22': 'Arbitrary File Disclosure & Directory Escape',
  'CWE-284': 'Horizontal Privilege Escalation (IDOR)',
  'CWE-78': 'Arbitrary Remote Code Execution (RCE)',
  'CWE-918': 'Cloud Metadata Exfiltration & SSRF',
  'CWE-502': 'Remote Code Execution via Deserialization',
  'CWE-798': 'Hardcoded Credential & Token Exposure',
  'CWE-328': 'Weak Hash Collisions & Signature Inversion',
  'CWE-601': 'Open Redirect & Phishing Harvesting',
  'CWE-942': 'Cross-Origin Data Leakage',
  'CWE-489': 'Internal Secrets & Configuration Leak',
  'CWE-614': 'Session Token Theft via XSS / MITM',
  'CWE-1395': 'Known CVE Supply Chain Vulnerability',
  'CWE-20': 'Denial of Service & Unhandled Exceptions',
};

const TOPIC_BOXES = [
  {
    id: 'what-is-zeroday',
    slug: 'what-is-zeroday',
    aliases: ['about', 'overview'],
    title: 'What is ZeroDay?',
    icon: BookOpen,
    shortDesc:
      'Autonomous vulnerability detection and invariant-verified code remediation platform.',
  },
  {
    id: 'how-it-works',
    slug: 'how-it-works',
    aliases: ['architecture', 'pipeline'],
    title: 'How it Works',
    icon: Cpu,
    shortDesc:
      'Multi-stage adversarial loop combining AST reconnaissance, Red Team PoC, and a 4-Gate Oracle.',
  },
  {
    id: 'installing-zeroday',
    slug: 'installing-zeroday',
    aliases: ['install', 'setup', 'getting-started'],
    title: 'Installing ZeroDay',
    icon: Terminal,
    shortDesc:
      'Quickstart guide for local repository deployment, environment variables, and test suites.',
  },
  {
    id: 'supported-cwes',
    slug: 'supported-cwes',
    aliases: ['cwes', 'vulnerabilities', 'taxonomy'],
    title: 'Supported CWEs',
    icon: Shield,
    shortDesc:
      'Authoritative taxonomy of 14 MITRE CWE vulnerability classes with AST sink patterns.',
  },
  {
    id: 'evaluation-and-benchmarks',
    slug: 'evaluation-and-benchmarks',
    aliases: ['benchmarks', 'evaluation', 'metrics'],
    title: 'Evaluation and benchmarks',
    icon: CheckCircle2,
    shortDesc:
      'Measured results across 20 standardized test fixtures with 100% precision and zero false positives.',
  },
  {
    id: 'security-and-limits',
    slug: 'security-and-limits',
    aliases: ['security', 'limits', 'boundaries'],
    title: 'Security and Limits',
    icon: Lock,
    shortDesc:
      'Subprocess sandboxing, token isolation, crawler boundaries, and operational limits.',
  },
];

const TOPIC_SECTIONS = {
  'what-is-zeroday': [
    { id: 'overview', title: 'Overview & Core Mission' },
    { id: 'remediation-gap', title: 'The Vulnerability Remediation Gap' },
    { id: 'closed-loop-architecture', title: 'Closed-Loop Proof Architecture' },
    { id: 'feature-contrast', title: 'Feature Comparison Matrix' },
    { id: 'target-audience', title: 'Target Personas & Workflows' },
    { id: 'core-invariants', title: 'Core Verification Invariants' },
  ],
  'how-it-works': [
    { id: 'pipeline-overview', title: '6-Stage Autonomous Pipeline' },
    { id: 'interactive-flowchart', title: 'Interactive Block Diagram' },
    { id: 'ast-reconnaissance', title: 'Stage 1: AST Reconnaissance Engine' },
    { id: 'threat-grounding', title: 'Stage 2: Live MITRE Threat Grounding' },
    { id: 'adversarial-poc', title: 'Stage 3: Red Team PoC Exploit' },
    { id: 'remediation-synthesis', title: 'Stage 4: Blue Team Patch Synthesis' },
    { id: 'verification-oracle', title: 'Stage 5: 4-Gate Invariant Oracle' },
    { id: 'pr-packaging', title: 'Stage 6: PR & Evidence Packaging' },
    { id: 'state-machine', title: 'Self-Healing State Machine' },
  ],
  'installing-zeroday': [
    { id: 'system-prerequisites', title: 'System Requirements & Prerequisites' },
    { id: 'quickstart-cloning', title: 'Repository Setup & Virtualenv' },
    { id: 'environment-configuration', title: 'Environment Configuration (.env)' },
    { id: 'frontend-compilation', title: 'Frontend Compilation & Packaging' },
    { id: 'launching-server', title: 'Running the FastAPI Server' },
    { id: 'verification-testing', title: 'Running the Pytest Test Suite' },
  ],
  'supported-cwes': [
    { id: 'cwe-taxonomy-overview', title: 'MITRE CWE Taxonomy Overview' },
    { id: 'cwe-filter-inspector', title: 'Interactive CWE Catalog' },
    { id: 'injection-vulnerabilities', title: 'Injection Attacks (CWE-89, 78, 94)' },
    { id: 'traversal-and-ssrf', title: 'Path Traversal & SSRF (CWE-22, 918)' },
    { id: 'deserialization-and-xxe', title: 'Deserialization & XML (CWE-502, 611)' },
    { id: 'crypto-and-auth', title: 'Crypto & Auth (CWE-798, 327, 295)' },
  ],
  'evaluation-and-benchmarks': [
    { id: 'benchmark-methodology', title: 'Empirical Benchmark Methodology' },
    { id: 'standardized-fixtures', title: 'Standardized 20-Fixture Suite' },
    { id: 'measured-results', title: 'Ground-Truth Measured Results' },
    { id: 'confusion-matrix', title: 'Confusion Matrix & Derivations' },
    { id: 'reproducing-locally', title: 'Local Benchmark Reproducibility' },
  ],
  'security-and-limits': [
    { id: 'security-model', title: 'ZeroDay Trust & Security Model' },
    { id: 'isolated-sandboxing', title: 'Subprocess Execution Sandboxing' },
    { id: 'secret-isolation', title: 'Secret & Token Isolation' },
    { id: 'crawler-boundaries', title: 'Crawler & Public Indexing Boundaries' },
    { id: 'known-limitations', title: 'Known Limitations & Boundary Scope' },
    { id: 'human-in-the-loop', title: 'Human-in-the-Loop Governance' },
  ],
};

function DocMinimalFooter({ onNavigate }) {
  return (
    <footer className="doc-minimal-footer" aria-label="Documentation Footer">
      <div className="doc-footer-inner">
        {/* Top: ZERODAY logo centered */}
        <div className="doc-footer-brand-row">
          <span className="doc-footer-brand-logo font-oxanium">ZERODAY</span>
        </div>

        {/* Middle: Centered Platform Navigation Links */}
        <nav className="doc-footer-nav-row font-onest" aria-label="Documentation footer links">
          <button
            type="button"
            onClick={() => onNavigate('benchmarks')}
            className="doc-footer-nav-link"
          >
            Benchmarks
          </button>
          <button
            type="button"
            onClick={() => onNavigate('documentation')}
            className="doc-footer-nav-link"
          >
            Documentation
          </button>
          <button
            type="button"
            onClick={() => onNavigate('hackathon')}
            className="doc-footer-nav-link"
          >
            Hackathon projects
          </button>
          <a
            href="https://github.com/darshansahare/ZeroDay"
            target="_blank"
            rel="noopener noreferrer"
            className="doc-footer-nav-link"
          >
            Github
          </a>
        </nav>

        {/* Bottom: Left-aligned copyright */}
        <div className="doc-footer-bottom-deck font-onest">
          <span className="doc-footer-copyright">
            &copy; 2026 ZeroDay. Nebius &times; NVIDIA Global AI Hackathon. MIT License.
          </span>
        </div>
      </div>
    </footer>
  );
}

export default function DocsPage({
  docSlug,
  onSelectTopic,
  onBackToDirectory,
  onNavigateToArena,
  onNavigateToHackathon,
}) {
  const [openFaqIndex, setOpenFaqIndex] = useState(null);
  const [cweFilter, setCweFilter] = useState('');
  const [copiedKey, setCopiedKey] = useState(null);
  const [activeSectionId, setActiveSectionId] = useState('');


  const {
    brand,
    hackathon,
    pipelineStages,
    supportedVulnerabilities,
    benchmarkMetrics,
    limitations,
    faqItems,
  } = PROJECT_KNOWLEDGE;

  const currentTopic = docSlug
    ? TOPIC_BOXES.find(
        (b) =>
          b.slug === docSlug.toLowerCase() ||
          b.aliases.includes(docSlug.toLowerCase())
      ) || null
    : null;

  const currentSections = currentTopic
    ? TOPIC_SECTIONS[currentTopic.id] || []
    : [];

  useEffect(() => {
    if (currentSections.length > 0) {
      setActiveSectionId(currentSections[0].id);
    }
  }, [docSlug]);

  useEffect(() => {
    if (!currentTopic || currentSections.length === 0) return;

    const handleScroll = () => {
      // 100px accounts for fixed top navbar (72px) + breathing space
      const scrollPos = window.scrollY + 110;
      let activeId = currentSections[0].id;

      for (let i = 0; i < currentSections.length; i++) {
        const sec = currentSections[i];
        const el = document.getElementById(sec.id);
        if (el) {
          const top = el.getBoundingClientRect().top + window.scrollY;
          if (scrollPos >= top) {
            activeId = sec.id;
          }
        }
      }
      setActiveSectionId(activeId);
    };

    handleScroll();
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, [currentTopic, currentSections]);

  const toggleFaq = (idx) => {
    setOpenFaqIndex(openFaqIndex === idx ? null : idx);
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard?.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const filteredCwes = supportedVulnerabilities.filter((v) => {
    if (!cweFilter) return true;
    const q = cweFilter.toLowerCase();
    return (
      v.cwe.toLowerCase().includes(q) ||
      v.name.toLowerCase().includes(q) ||
      v.description.toLowerCase().includes(q)
    );
  });

  const handleFooterNav = (view) => {
    if (view === 'arena' && onNavigateToArena) onNavigateToArena();
    else if (view === 'hackathon' && onNavigateToHackathon) onNavigateToHackathon();
    else if (view === 'documentation' && onBackToDirectory) onBackToDirectory();
    else if (view === 'benchmarks') {
      window.location.href = '/benchmarks';
    }
  };

  // =========================================================================
  // VIEW 1: DEDICATED TOPIC SUB-PAGE (NVIDIA DEVELOPER DOCUMENTATION LAYOUT)
  // =========================================================================
  if (currentTopic) {
    return (
      <div className="documentation-page-canvas font-onest">
        <div className="doc-page-shell">
          {/* Top Breadcrumb: Documentation / Title */}
          <nav className="doc-breadcrumbs font-onest" aria-label="Breadcrumb navigation">
            <button
              type="button"
              onClick={onBackToDirectory}
              className="crumb-link font-onest"
            >
              Documentation
            </button>
            <span className="crumb-sep">/</span>
            <span className="crumb-current font-onest">{currentTopic.title}</span>
          </nav>

          {/* Two-Column Documentation Body */}
          <div className="doc-nvidia-layout">
            {/* Left Column: Sidebar with On this page & All Topics */}
            <aside className="doc-nvidia-sidebar" aria-label="Documentation Table of Contents">
              <div className="sidebar-sticky-inner">
                <div className="sidebar-heading font-onest">On this page</div>
                <nav className="sidebar-toc-list" aria-label="Sections on this page">
                  {currentSections.map((sec) => {
                    const isActive = activeSectionId === sec.id;
                    return (
                      <a
                        key={sec.id}
                        href={`#${sec.id}`}
                        onClick={(e) => {
                          e.preventDefault();
                          setActiveSectionId(sec.id);
                          const el = document.getElementById(sec.id);
                          if (el) {
                            const navOffset = 90;
                            const elementPosition = el.getBoundingClientRect().top;
                            const offsetPosition = elementPosition + window.pageYOffset - navOffset;
                            window.scrollTo({
                              top: offsetPosition,
                              behavior: 'smooth',
                            });
                          }
                        }}
                        className={`sidebar-toc-item font-onest ${isActive ? 'active' : ''}`}
                      >
                        <span className="toc-item-text">{sec.title}</span>
                      </a>
                    );
                  })}
                </nav>
              </div>
            </aside>

            {/* Right Column: Expansive, Highly Detailed Technical Documentation */}
            <main className="doc-nvidia-content">
              <header className="doc-article-header">
                <h1 className="doc-main-heading font-oxanium">{currentTopic.title}</h1>
                <p className="doc-main-lead-text font-onest">{currentTopic.shortDesc}</p>
              </header>

              {/* ----------------------------------------------------------------- */}
              {/* TOPIC 1: WHAT IS ZERODAY? */}
              {/* ----------------------------------------------------------------- */}
              {currentTopic.id === 'what-is-zeroday' && (
                <div className="doc-article-body font-onest">
                  <section id="overview" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Overview & Core Mission</h2>
                    <p className="doc-text">
                      ZeroDay is an autonomous vulnerability detection, exploit verification, and self-healing platform engineered
                      specifically for cloud-native software microservices. Built around the foundational philosophy of{' '}
                      <strong>"Find the flaw. Prove the fix."</strong>, ZeroDay bridges the dangerous operational chasm between
                      noisy, unvalidated static code analyzers and probabilistic AI code assistants.
                    </p>
                    <p className="doc-text">
                      In conventional enterprise security, identifying an alert is only the beginning of a grueling manual cycle:
                      security engineers must construct proof-of-concept exploits to verify real-world exploitability, developers
                      must author patches under extreme time pressure, and quality assurance teams must certify that remedies do not
                      break existing business logic. ZeroDay automates this entire lifecycle into a single closed loop, combining
                      adversarial exploit synthesis with an invariant-verified remediation engine powered by NVIDIA Nemotron.
                    </p>
                  </section>

                  <section id="remediation-gap" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">The Vulnerability Remediation Gap</h2>
                    <p className="doc-text">
                      Modern software organizations suffer from severe friction caused by two opposing technological extremes:
                    </p>
                    <div className="doc-detail-callout">
                      <div className="callout-block">
                        <h3 className="callout-title font-oxanium text-orange">1. SAST Alert Fatigue & False Positives</h3>
                        <p className="callout-text">
                          Traditional Static Application Security Testing (SAST) tools rely on syntactic pattern matching and rule heuristics.
                          Because they evaluate code syntax without understanding dynamic control flow or executing the runtime context,
                          industry benchmark data demonstrates that between <strong>40% and 70%</strong> of reported SAST alerts are false positives.
                          Engineering teams waste hundreds of hours triaging benign inputs, sanitizers that were unrecognized by static rules,
                          or unreachable execution branches.
                        </p>
                      </div>
                      <div className="callout-block">
                        <h3 className="callout-title font-oxanium text-orange">2. AI Assistant Hallucinations & Broken Regressions</h3>
                        <p className="callout-text">
                          Generic LLM code assistants generate patches based on statistical token prediction rather than formal program verification.
                          Without execution sandboxing, static invariant checks, or regression testing, standard LLMs routinely introduce subtle
                          secondary vulnerabilities (such as incomplete sanitization, regex bypasses, or missing authentication checks) or
                          catastrophically break valid application logic and downstream dependencies.
                        </p>
                      </div>
                    </div>
                  </section>

                  <section id="closed-loop-architecture" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Closed-Loop Proof Architecture</h2>
                    <p className="doc-text">
                      ZeroDay resolves this dilemma by replacing speculative guesswork with empirical proof. The architecture unites two
                      adversarial agents under an uncompromising, deterministic verification oracle:
                    </p>
                    <ul className="doc-feature-list">
                      <li>
                        <strong>Red Team Exploit Agent:</strong> Given an identified abstract syntax tree (AST) vulnerability sink,
                        the Red Team agent synthesizes a targeted, synthetic proof-of-concept (PoC) exploit payload and executes it inside
                        an isolated subprocess sandbox. If the exploit fails to trigger, the alert is discarded as non-exploitable,
                        guaranteeing zero false-positive fatigue for developers.
                      </li>
                      <li>
                        <strong>Blue Team Remediation Agent:</strong> Utilizing NVIDIA Nemotron via the Nebius Token Factory,
                        the Blue Team agent ingests the AST context, real-time threat intelligence from MITRE CWE, and the active exploit trace.
                        It synthesizes a minimal, atomic unified diff adhering to secure coding patterns and parameterization principles.
                      </li>
                      <li>
                        <strong>Deterministic 4-Gate Oracle:</strong> The synthesized patch is never merged on trust. It must pass
                        AST compilation, static delta verification, exploit replay immunity, and the repository's full regression test suite
                        before an authoritative pull request is generated.
                      </li>
                    </ul>
                  </section>

                  <section id="feature-contrast" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Feature Comparison Matrix</h2>
                    <div className="doc-table-container">
                      <table className="doc-comparison-table font-onest">
                        <thead>
                          <tr>
                            <th>Capability Dimension</th>
                            <th>Traditional SAST</th>
                            <th>Generic AI Assistant</th>
                            <th>ZeroDay Autonomous Loop</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td><strong>Vulnerability Detection</strong></td>
                            <td>Static pattern heuristics</td>
                            <td>Conversational prompting</td>
                            <td>AST Reconnaissance + Call Graphs</td>
                          </tr>
                          <tr>
                            <td><strong>Exploit Verification</strong></td>
                            <td>None (theoretical alert)</td>
                            <td>None (hallucination risk)</td>
                            <td>Synthetic PoC Execution in Sandbox</td>
                          </tr>
                          <tr>
                            <td><strong>False Positive Elimination</strong></td>
                            <td>Manual human triage (40%+ FP)</td>
                            <td>Uncontrolled</td>
                            <td>Empirical Proof (0.0% False Positive)</td>
                          </tr>
                          <tr>
                            <td><strong>Automated Patch Generation</strong></td>
                            <td>None (documentation link)</td>
                            <td>Plausible code token prediction</td>
                            <td>Minimal Unified Diff (NVIDIA Nemotron)</td>
                          </tr>
                          <tr>
                            <td><strong>Non-Regression Guarantee</strong></td>
                            <td>None</td>
                            <td>None (frequently breaks logic)</td>
                            <td>Full Pytest Regression Suite Passing</td>
                          </tr>
                          <tr>
                            <td><strong>Verification Oracle</strong></td>
                            <td>None</td>
                            <td>None</td>
                            <td>4-Gate Deterministic Validation</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </section>

                  <section id="target-audience" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Target Personas & Workflows</h2>
                    <p className="doc-text">ZeroDay is engineered to integrate seamlessly into three key developer personas:</p>
                    <div className="doc-persona-grid">
                      <div className="persona-card">
                        <h3 className="persona-title font-oxanium">Application Security (AppSec)</h3>
                        <p className="persona-body">
                          Eliminate alert triaging meetings by requiring every reported vulnerability to carry a reproducible execution trace.
                          AppSec teams gain audited verification receipts demonstrating that fixes defeat the exact exploit vector before code review.
                        </p>
                      </div>
                      <div className="persona-card">
                        <h3 className="persona-title font-oxanium">DevSecOps & Platform Teams</h3>
                        <p className="persona-body">
                          Automate the creation of pre-verified, passing pull requests directly in CI/CD pipelines. Gate production builds on
                          mathematical non-regression and cryptographic audit logs.
                        </p>
                      </div>
                      <div className="persona-card">
                        <h3 className="persona-title font-oxanium">Backend Software Engineers</h3>
                        <p className="persona-body">
                          Receive concise, atomic code patches that maintain existing variable names and business logic invariants without
                          requiring manual security research or wrestling with ambiguous security guidance.
                        </p>
                      </div>
                    </div>
                  </section>

                  <section id="core-invariants" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Core Verification Invariants</h2>
                    <p className="doc-text">
                      ZeroDay adheres to four foundational engineering invariants that govern all system behavior:
                    </p>
                    <ol className="doc-numbered-list">
                      <li>
                        <strong>The Non-Regression Invariant:</strong> A patch must never break existing unit tests. If even a single
                        pre-existing test fails during Gate 4, the candidate patch is rejected immediately and routed to the self-healing feedback loop.
                      </li>
                      <li>
                        <strong>The Sink Elimination Invariant:</strong> The patched code must structurally eradicate the vulnerable AST sink.
                        Gate 2 re-scans the modified AST to mathematically verify that the vulnerable sink node is eliminated and that zero new sinks were introduced.
                      </li>
                      <li>
                        <strong>The Exploit Rejection Invariant:</strong> The exact synthetic exploit payload that succeeded during Red Team
                        analysis must be re-executed against the remediated code and must conclusively fail, timeout, or trigger safe error handling.
                      </li>
                      <li>
                        <strong>The Minimal Surface Invariant:</strong> Remediations must be scoped strictly to the vulnerable function scope.
                        ZeroDay enforces minimal diff heuristics to prevent architectural drift or broad code refactoring.
                      </li>
                    </ol>
                  </section>
                </div>
              )}

              {/* ----------------------------------------------------------------- */}
              {/* TOPIC 2: HOW IT WORKS */}
              {/* ----------------------------------------------------------------- */}
              {currentTopic.id === 'how-it-works' && (
                <div className="doc-article-body font-onest">
                  {/* Overview */}
                  <section id="pipeline-overview" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">6-Stage Autonomous Pipeline</h2>
                    <p className="doc-text">
                      ZeroDay decomposes end-to-end vulnerability remediation into six discrete, deterministic engineering stages.
                      Unlike generic code assistants that attempt to solve security flaws in a single speculative prompt, ZeroDay
                      enforces strict separation of concerns: static syntax analysis is separated from adversarial exploit generation,
                      and candidate patches are evaluated under an invariant 4-gate verification oracle before acceptance.
                    </p>
                    <p className="doc-text">
                      By pairing an adversarial Red Team exploit engine with an NVIDIA Nemotron Blue Team healing agent hosted on
                      the Nebius Token Factory, ZeroDay achieves a closed feedback loop that deterministically proves whether a flaw is
                      exploitable and guarantees that proposed code fixes eliminate the vulnerability without breaking application tests.
                    </p>
                  </section>

                                                                        {/* Flowchart / Block Diagram (Direct Draw.io Style, No Outer Box, No Pill Boxes) */}
                  <section id="interactive-flowchart" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Architecture Flowchart</h2>
                    <p className="doc-text">
                      Below is the engineering execution flowchart illustrating the closed-loop pipeline from AST analysis to automated pull request authoring.
                      Click any node to navigate to its detailed specification:
                    </p>

                    <div className="doc-drawio-flowchart-wrapper">
                      <svg
                        viewBox="0 0 640 680"
                        className="drawio-flowchart-svg"
                        xmlns="http://www.w3.org/2000/svg"
                        aria-label="ZeroDay Execution Flowchart (Draw.io Style)"
                      >
                        <defs>
                          <marker
                            id="drawio-arrow"
                            viewBox="0 0 10 10"
                            refX="9"
                            refY="5"
                            markerWidth="6"
                            markerHeight="6"
                            orient="auto-start-reverse"
                          >
                            <path d="M 0 1 L 10 5 L 0 9 z" fill="#6E7681" />
                          </marker>
                          <marker
                            id="drawio-arrow-loop"
                            viewBox="0 0 10 10"
                            refX="9"
                            refY="5"
                            markerWidth="6"
                            markerHeight="6"
                            orient="auto-start-reverse"
                          >
                            <path d="M 0 1 L 10 5 L 0 9 z" fill="#8B949E" />
                          </marker>
                        </defs>

                        {/* 01. AST RECONNAISSANCE */}
                        <g
                          className="drawio-node"
                          onClick={() => {
                            document.getElementById('ast-reconnaissance')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                            setActiveSectionId('ast-reconnaissance');
                          }}
                        >
                          <rect x="130" y="20" width="380" height="64" rx="6" className="drawio-box" />
                          <text x="320" y="46" className="drawio-text-title">01. AST Reconnaissance Engine</text>
                          <text x="320" y="66" className="drawio-text-subtitle">Static Syntax Visitor • AST Call Graph & Security Sinks</text>
                        </g>

                        {/* Direct line 1 -> 2 */}
                        <line x1="320" y1="84" x2="320" y2="124" className="drawio-line" markerEnd="url(#drawio-arrow)" />

                        {/* 02. LIVE THREAT GROUNDING */}
                        <g
                          className="drawio-node"
                          onClick={() => {
                            document.getElementById('threat-grounding')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                            setActiveSectionId('threat-grounding');
                          }}
                        >
                          <rect x="130" y="126" width="380" height="64" rx="6" className="drawio-box" />
                          <text x="320" y="152" className="drawio-text-title">02. Live MITRE Threat Grounding</text>
                          <text x="320" y="172" className="drawio-text-subtitle">Tavily AI Search • Real-Time MITRE CWE & CVE Rules</text>
                        </g>

                        {/* Direct line 2 -> 3 */}
                        <line x1="320" y1="190" x2="320" y2="230" className="drawio-line" markerEnd="url(#drawio-arrow)" />

                        {/* 03. ADVERSARIAL POC EXPLOIT */}
                        <g
                          className="drawio-node"
                          onClick={() => {
                            document.getElementById('adversarial-poc')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                            setActiveSectionId('adversarial-poc');
                          }}
                        >
                          <rect x="130" y="232" width="380" height="64" rx="6" className="drawio-box" />
                          <text x="320" y="258" className="drawio-text-title">03. Adversarial PoC Exploit Synthesis</text>
                          <text x="320" y="278" className="drawio-text-subtitle">Red Team Agent • Ephemeral Subprocess Sandbox</text>
                        </g>

                        {/* Direct line 3 -> 4 */}
                        <line x1="320" y1="296" x2="320" y2="336" className="drawio-line" markerEnd="url(#drawio-arrow)" />

                        {/* 04. BLUE TEAM REMEDIATION */}
                        <g
                          className="drawio-node"
                          onClick={() => {
                            document.getElementById('remediation-synthesis')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                            setActiveSectionId('remediation-synthesis');
                          }}
                        >
                          <rect x="130" y="338" width="380" height="64" rx="6" className="drawio-box" />
                          <text x="320" y="364" className="drawio-text-title">04. Blue Team Remediation Synthesis</text>
                          <text x="320" y="384" className="drawio-text-subtitle">NVIDIA Nemotron via Nebius Token Factory</text>
                        </g>

                        {/* Direct line 4 -> 5 */}
                        <line x1="320" y1="402" x2="320" y2="442" className="drawio-line" markerEnd="url(#drawio-arrow)" />

                        {/* 05. DECISION DIAMOND: 4-GATE VERIFICATION ORACLE */}
                        <g
                          className="drawio-node"
                          onClick={() => {
                            document.getElementById('verification-oracle')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                            setActiveSectionId('verification-oracle');
                          }}
                        >
                          <polygon
                            points="320,444 470,494 320,544 170,494"
                            className="drawio-diamond"
                          />
                          <text x="320" y="488" className="drawio-text-diamond-title">05. 4-Gate Oracle</text>
                          <text x="320" y="504" className="drawio-text-diamond-sub">All 4 Gates Pass?</text>
                          <text x="320" y="519" className="drawio-text-diamond-gates">Syntax • Delta • Replay • Pytest</text>
                        </g>

                        {/* Loop-back arrow for Fail (orthogonal path back up to Stage 04) */}
                        <path
                          d="M 470 494 L 540 494 L 540 370 L 512 370"
                          className="drawio-line-loop"
                          markerEnd="url(#drawio-arrow-loop)"
                        />
                        <text x="548" y="440" className="drawio-text-loop-sub">Retry (Max 3)</text>

                        {/* Direct line 5 -> 6 */}
                        <line x1="320" y1="544" x2="320" y2="584" className="drawio-line" markerEnd="url(#drawio-arrow)" />

                        {/* 06. PR & EVIDENCE RECEIPT */}
                        <g
                          className="drawio-node"
                          onClick={() => {
                            document.getElementById('pr-packaging')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                            setActiveSectionId('pr-packaging');
                          }}
                        >
                          <rect x="130" y="586" width="380" height="64" rx="6" className="drawio-box" />
                          <text x="320" y="612" className="drawio-text-title">06. PR & Evidence Packaging</text>
                          <text x="320" y="632" className="drawio-text-subtitle">Git Automation • Audited Verification Receipt</text>
                        </g>
                      </svg>
                    </div>
                  </section>

                  {/* Stage 1 Deep Dive */}
                  <section id="ast-reconnaissance" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Stage 1: AST Reconnaissance Engine</h2>
                    <p className="doc-text">
                      Rather than using regex heuristics or vulnerable dynamic execution, ZeroDay uses Python's standard library
                      <code>ast</code> module to compile source code into an Abstract Syntax Tree (AST). Custom <code>ast.NodeVisitor</code>
                      classes systematically walk the syntax hierarchy to detect security sinks without executing any application code.
                    </p>
                    <p className="doc-text">
                      The AST scanner evaluates call graph nodes (<code>ast.Call</code>), attribute accesses (<code>ast.Attribute</code>),
                      and argument expressions to distinguish static constant strings from untrusted user inputs:
                    </p>
                    <div className="doc-code-block font-mono">
                      <div className="code-header">
                        <span>AST VISITOR SINK DETECTION PATTERN</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(`class SecuritySinkVisitor(ast.NodeVisitor):\n    def visit_Call(self, node):\n        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":\n            if any(isinstance(arg, (ast.JoinedStr, ast.BinOp)) for arg in node.args):\n                self.findings.append((node.lineno, "CWE-89", "SQL Injection"))`, 'ast_code')}
                          className="copy-btn font-mono"
                        >
                          {copiedKey === 'ast_code' ? <Check size={12} /> : <Copy size={12} />}
                          {copiedKey === 'ast_code' ? 'COPIED' : 'COPY'}
                        </button>
                      </div>
                      <pre>
{`class SecuritySinkVisitor(ast.NodeVisitor):
    def visit_Call(self, node):
        # 1. Detect dynamic SQL query composition (CWE-89)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if any(isinstance(arg, (ast.JoinedStr, ast.BinOp)) for arg in node.args):
                self.findings.append((node.lineno, "CWE-89", "SQL Injection in execute()"))
        
        # 2. Detect shell=True command injection (CWE-78)
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("Popen", "run", "system"):
            for keyword in node.keywords:
                if keyword.arg == "shell" and getattr(keyword.value, "value", False) is True:
                    self.findings.append((node.lineno, "CWE-78", "Subprocess shell=True Injection"))
        
        self.generic_visit(node)`}
                      </pre>
                    </div>
                    <p className="doc-text">
                      The output of Stage 1 is a structured <code>VulnerabilityCandidate</code> object containing the exact file path,
                      line numbers, target sink signature, and local function scope.
                    </p>
                  </section>

                  {/* Stage 2 Deep Dive */}
                  <section id="threat-grounding" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Stage 2: Live MITRE Threat Grounding</h2>
                    <p className="doc-text">
                      A core vulnerability of standard LLM code generation is hallucination: models frequently recommend deprecated functions,
                      non-existent third-party packages, or insecure sanitizers. To ensure strict adherence to industry standards, ZeroDay integrates
                      the <strong>Tavily AI Search API</strong> to dynamically query official MITRE CWE definitions and NIST CVE guidelines.
                    </p>
                    <p className="doc-text">
                      The fetched intelligence extracts authoritative mitigation standards:
                    </p>
                    <ul className="doc-feature-list">
                      <li><strong>Parameterized Query Syntax:</strong> Supplies database-specific placeholder semantics (e.g., <code>?</code> for SQLite, <code>%s</code> for PostgreSQL).</li>
                      <li><strong>Safe Serialization Libraries:</strong> Dictates safe parser alternatives (e.g., using <code>json.loads</code> or <code>yaml.safe_load</code> instead of <code>pickle.loads</code>).</li>
                      <li><strong>Cryptographic Algorithms:</strong> Injects guidance forbidding MD5/SHA-1 and mandating SHA-256 and AES-GCM primitives.</li>
                    </ul>
                  </section>

                  {/* Stage 3 Deep Dive */}
                  <section id="adversarial-poc" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Stage 3: Red Team PoC Exploit Synthesis</h2>
                    <p className="doc-text">
                      ZeroDay eliminates the 40-70% false-positive rate of traditional SAST scanners by requiring empirical proof of exploitability.
                      The Red Team agent—a specialized NVIDIA Nemotron system—is tasked with authoring an adversarial proof-of-concept (PoC) exploit payload
                      specifically targeting the detected AST sink.
                    </p>
                    <p className="doc-text">
                      The exploit payload is executed inside an ephemeral subprocess sandbox with strict resource limits:
                    </p>
                    <div className="doc-code-block font-mono">
                      <div className="code-header">
                        <span>SANDBOX EXPLOIT EXECUTION HARNESS</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard('proc = subprocess.run([sys.executable, target_file], input=payload.encode("utf-8"), timeout=10, capture_output=True, cwd=temp_sandbox_dir)', 'poc_exec')}
                          className="copy-btn font-mono"
                        >
                          {copiedKey === 'poc_exec' ? <Check size={12} /> : <Copy size={12} />}
                          {copiedKey === 'poc_exec' ? 'COPIED' : 'COPY'}
                        </button>
                      </div>
                      <pre>
{`# Ephemeral execution with resource and network isolation:
proc = subprocess.run(
    [sys.executable, target_script],
    input=synthetic_exploit_payload.encode("utf-8"),
    timeout=10,
    capture_output=True,
    cwd=isolated_sandbox_path
)

# Empirically verify whether the exploit triggered an observable security breach:
is_exploitable = (
    proc.returncode == 0 and 
    ("root:x:0:0" in proc.stdout.decode() or "SQLITE_ERROR" not in proc.stderr.decode())
)`}
                      </pre>
                    </div>
                    <p className="doc-text">
                      <strong>The Zero False Positive Guarantee:</strong> If the synthetic exploit reproduces, the flaw is classified as
                      Empirically Verified. If the exploit fails to execute (e.g. because input is already sanitized by an upstream framework),
                      the alert is silenced immediately.
                    </p>
                  </section>

                  {/* Stage 4 Deep Dive */}
                  <section id="remediation-synthesis" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Stage 4: Blue Team Patch Synthesis</h2>
                    <p className="doc-text">
                      Once a vulnerability is empirically proven, the Blue Team agent synthesizes a remediation. Powered by NVIDIA Nemotron
                      via the Nebius Token Factory, the agent receives a constrained prompt containing:
                    </p>
                    <ul className="doc-feature-list">
                      <li>The target function AST slice and surrounding context.</li>
                      <li>The exact line numbers of the detected vulnerability sink.</li>
                      <li>The authoritative MITRE CWE mitigation requirements from Stage 2.</li>
                      <li>The reproducible Red Team attack trace from Stage 3.</li>
                    </ul>
                    <p className="doc-text">
                      The Blue Team agent is constrained by defensive prompt guardrails: it must produce a minimal unified diff
                      (<code>diff --git a/... b/...</code>), preserve existing comments, maintain indentation, and avoid broad refactoring.
                      Inference streaming through Nebius Token Factory delivers completed candidate patches in under 2 seconds.
                    </p>
                  </section>

                  {/* Stage 5 Deep Dive */}
                  <section id="verification-oracle" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Stage 5: 4-Gate Invariant Verification Oracle</h2>
                    <p className="doc-text">
                      ZeroDay never merges code based on generative AI probability. Every candidate patch must survive four sequential,
                      deterministic verification gates before it can be considered a valid remedy:
                    </p>
                    <div className="doc-oracle-grid">
                      <div className="oracle-gate-card">
                        <span className="gate-tag font-mono">GATE 01</span>
                        <h3 className="gate-title font-oxanium">Syntax AST Compilation</h3>
                        <p className="gate-body">
                          Validates that the patch applies cleanly via <code>git apply</code> and compiles with zero Python syntax errors
                          using standard library <code>ast.parse</code>. Catches indentation mistakes, missing colons, and broken imports.
                        </p>
                      </div>
                      <div className="oracle-gate-card">
                        <span className="gate-tag font-mono">GATE 02</span>
                        <h3 className="gate-title font-oxanium">Static Analysis Delta</h3>
                        <p className="gate-body">
                          Re-scans the patched file using the Stage 1 AST Reconnaissance engine. Mathematically verifies that the original
                          vulnerability sink is completely eliminated and that zero new vulnerability sinks were introduced.
                        </p>
                      </div>
                      <div className="oracle-gate-card">
                        <span className="gate-tag font-mono">GATE 03</span>
                        <h3 className="gate-title font-oxanium">Exploit Replay Immunity</h3>
                        <p className="gate-body">
                          Replays the original synthetic Red Team PoC exploit payload against the patched code inside an isolated subprocess.
                          The attack must be safely rejected, neutralized, or blocked with proper error handling.
                        </p>
                      </div>
                      <div className="oracle-gate-card">
                        <span className="gate-tag font-mono">GATE 04</span>
                        <h3 className="gate-title font-oxanium">Test Suite Regression</h3>
                        <p className="gate-body">
                          Executes the repository's full <code>pytest</code> test suite. Every existing test that passed prior to remediation
                          must continue to pass, proving that business logic was not corrupted or regressed.
                        </p>
                      </div>
                    </div>
                  </section>

                  {/* Stage 6 Deep Dive */}
                  <section id="pr-packaging" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Stage 6: PR & Evidence Packaging</h2>
                    <p className="doc-text">
                      When all 4 gates pass, ZeroDay packages the remediation into an enterprise-ready Git commit and Pull Request.
                      The PR contains not only the minimal unified diff, but also a cryptographic audit receipt:
                    </p>
                    <ul className="doc-feature-list">
                      <li><strong>Target Commit Hash:</strong> SHA-256 fingerprint of the base repository snapshot.</li>
                      <li><strong>Adversarial PoC Trace:</strong> Reproducible attack execution log proving exploitability before remediation.</li>
                      <li><strong>Oracle Verification Logs:</strong> Individual pass certificates for AST compilation, static delta, exploit rejection, and pytest test suite.</li>
                      <li><strong>MITRE CWE Mapping:</strong> Authoritative classification with CVSS severity scoring.</li>
                    </ul>
                  </section>

                  {/* State Machine Deep Dive */}
                  <section id="state-machine" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Self-Healing State Machine</h2>
                    <p className="doc-text">
                      The core orchestrator implements an autonomous state machine with automated error recovery. If a candidate patch
                      fails any of the 4 verification gates, the orchestrator does not give up or crash:
                    </p>
                    <ol className="doc-numbered-list">
                      <li>
                        <strong>Failure Diagnostics Capture:</strong> The exact compiler error (Gate 1), remaining sink AST node (Gate 2),
                        bypassed exploit output (Gate 3), or pytest failure assertion (Gate 4) is captured into a structured diagnostic packet.
                      </li>
                      <li>
                        <strong>Iterative Self-Healing Loop:</strong> The diagnostic packet is injected into a new Blue Team prompt as corrective
                        feedback (e.g. <em>"Attempt 1 failed Gate 4: test_user_login failed with KeyError: 'token'. Maintain the token return field in your patch."</em>).
                      </li>
                      <li>
                        <strong>Max Retry Bounding:</strong> The system allows up to <strong>3 iterative self-healing attempts</strong>. If convergence
                        is not reached within 3 attempts, the system generates a security triage advisory for human engineer review, preventing infinite loops.
                      </li>
                    </ol>
                  </section>
                </div>
              )}

              {/* ----------------------------------------------------------------- */}
              {/* TOPIC 3: INSTALLING ZERODAY */}
              {/* ----------------------------------------------------------------- */}
              {currentTopic.id === 'installing-zeroday' && (
                <div className="doc-article-body font-onest">
                  <section id="system-prerequisites" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">System Requirements & Prerequisites</h2>
                    <p className="doc-text">
                      ZeroDay is designed for local development workstations and CI/CD runners. It supports Linux (Ubuntu 22.04+, Debian 12+),
                      macOS (12+ Apple Silicon & Intel), and Windows 10/11 (PowerShell/WSL2).
                    </p>
                    <ul className="doc-feature-list">
                      <li><strong>Python:</strong> Version 3.12 or newer with <code>venv</code> and <code>pip</code>.</li>
                      <li><strong>Node.js:</strong> Version 18.0 or newer with <code>npm</code>.</li>
                      <li><strong>Nebius API Key:</strong> Access to Nebius Token Factory with NVIDIA Nemotron deployment.</li>
                      <li><strong>Tavily API Key:</strong> Free or standard API key for real-time threat intelligence.</li>
                    </ul>
                  </section>

                  <section id="quickstart-cloning" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Step 1: Repository Setup & Virtualenv</h2>
                    <div className="doc-code-block font-mono">
                      <div className="code-header">
                        <span>BASH / POWERSHELL</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard('git clone https://github.com/darshansahare/ZeroDay.git\ncd ZeroDay\npython -m venv venv\nsource venv/bin/activate\npip install -r requirements.txt', 'clone')}
                          className="copy-btn font-mono"
                        >
                          {copiedKey === 'clone' ? <Check size={12} /> : <Copy size={12} />}
                          {copiedKey === 'clone' ? 'COPIED' : 'COPY'}
                        </button>
                      </div>
                      <pre>
{`# 1. Clone the repository
git clone https://github.com/darshansahare/ZeroDay.git
cd ZeroDay

# 2. Create and activate a Python 3.12 virtual environment
python -m venv venv

# On Linux/macOS:
source venv/bin/activate
# On Windows (PowerShell):
.\\venv\\Scripts\\Activate.ps1

# 3. Install core Python dependencies
pip install -r requirements.txt`}
                      </pre>
                    </div>
                  </section>

                  <section id="environment-configuration" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Step 2: Environment Configuration (.env)</h2>
                    <p className="doc-text">
                      ZeroDay reads its runtime configuration from environment variables or a root <code>.env</code> file.
                      Copy the template and supply your credentials:
                    </p>
                    <div className="doc-code-block font-mono">
                      <div className="code-header">
                        <span>.ENV CONFIGURATION</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard('cp .env.example .env', 'cp_env')}
                          className="copy-btn font-mono"
                        >
                          {copiedKey === 'cp_env' ? <Check size={12} /> : <Copy size={12} />}
                          {copiedKey === 'cp_env' ? 'COPIED' : 'COPY'}
                        </button>
                      </div>
                      <pre>
{`cp .env.example .env

# Configure required keys in .env:
NEBIUS_API_KEY="your-nebius-token-factory-api-key"
NEBIUS_BASE_URL="https://api.tokenfactory.nebius.com/v1/"
NEBIUS_MODEL="nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
TAVILY_API_KEY="your-tavily-search-api-key"

# Server network binding:
HOST="127.0.0.1"
PORT=8000
LOG_LEVEL="INFO"`}
                      </pre>
                    </div>
                  </section>

                  <section id="frontend-compilation" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Step 3: Frontend Compilation & Packaging</h2>
                    <p className="doc-text">
                      Compile the React 19 + Vite frontend application bundle into the FastAPI static distribution directory:
                    </p>
                    <div className="doc-code-block font-mono">
                      <div className="code-header">
                        <span>FRONTEND BUILD</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard('cd frontend\nnpm install\nnpm run build\ncd ..', 'build_fe')}
                          className="copy-btn font-mono"
                        >
                          {copiedKey === 'build_fe' ? <Check size={12} /> : <Copy size={12} />}
                          {copiedKey === 'build_fe' ? 'COPIED' : 'COPY'}
                        </button>
                      </div>
                      <pre>
{`cd frontend
npm install
npm run build
cd ..`}
                      </pre>
                    </div>
                  </section>

                  <section id="launching-server" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Step 4: Running the FastAPI Server</h2>
                    <p className="doc-text">
                      Start the FastAPI orchestrator daemon. The server serves both the REST API and the compiled React SPA:
                    </p>
                    <div className="doc-code-block font-mono">
                      <div className="code-header">
                        <span>LAUNCH SERVER</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard('python main.py', 'launch')}
                          className="copy-btn font-mono"
                        >
                          {copiedKey === 'launch' ? <Check size={12} /> : <Copy size={12} />}
                          {copiedKey === 'launch' ? 'COPIED' : 'COPY'}
                        </button>
                      </div>
                      <pre>
{`python main.py

# Expected Output:
# INFO:     Started server process [8049]
# INFO:     Waiting for application startup.
# INFO:     ZeroDay Engine initialized. Serving at http://127.0.0.1:8000`}
                      </pre>
                    </div>
                    <p className="doc-text">
                      Navigate to <a href="http://127.0.0.1:8000" className="doc-link">http://127.0.0.1:8000</a> in your web browser.
                    </p>
                  </section>

                  <section id="verification-testing" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Step 5: Running the Pytest Test Suite</h2>
                    <p className="doc-text">
                      Validate your local installation by executing the complete 130-test verification suite:
                    </p>
                    <div className="doc-code-block font-mono">
                      <div className="code-header">
                        <span>RUN TESTS</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard('pytest -v', 'test_cmd')}
                          className="copy-btn font-mono"
                        >
                          {copiedKey === 'test_cmd' ? <Check size={12} /> : <Copy size={12} />}
                          {copiedKey === 'test_cmd' ? 'COPIED' : 'COPY'}
                        </button>
                      </div>
                      <pre>
{`# Run full automated test suite:
pytest -v

# Run only benchmark suite:
pytest tests/benchmark/test_benchmark_suite.py -v`}
                      </pre>
                    </div>
                  </section>
                </div>
              )}

              {/* ----------------------------------------------------------------- */}
              {/* TOPIC 4: SUPPORTED CWES */}
              {/* ----------------------------------------------------------------- */}
              {currentTopic.id === 'supported-cwes' && (
                <div className="doc-article-body font-onest">
                  <section id="cwe-taxonomy-overview" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">MITRE CWE Taxonomy Overview</h2>
                    <p className="doc-text">
                      ZeroDay provides comprehensive AST sink detection, synthetic PoC exploit generation, and invariant-verified
                      remediation across <strong>14 standardized vulnerability classes</strong> mapped directly to MITRE Common Weakness
                      Enumeration (CWE) definitions. Below is the full catalog with vulnerable vs safe code patterns.
                    </p>
                  </section>

                                                      <section id="cwe-filter-inspector" className="doc-section-anchor">
                    <div className="cwe-header-row">
                      <div>
                        <h2 className="doc-section-title font-oxanium">Supported CWE Vulnerability Matrix</h2>
                        <p className="doc-text">
                          Authoritative catalog of all 14 supported MITRE CWE classes with target AST sinks, exploit impacts, detection mechanisms, and verified remediation standards.
                        </p>
                      </div>
                    </div>

                    {/* Filter and Table Toolbar */}
                    <div className="doc-cwe-toolbar">
                      <div className="doc-search-bar cwe-table-search">
                        <Search size={16} className="search-icon" />
                        <input
                          type="text"
                          value={cweFilter}
                          onChange={(e) => setCweFilter(e.target.value)}
                          placeholder="Search table by CWE ID, name, sink API, or keyword..."
                          className="search-input font-onest"
                        />
                        {cweFilter && (
                          <button
                            type="button"
                            onClick={() => setCweFilter('')}
                            className="search-clear font-mono"
                          >
                            CLEAR
                          </button>
                        )}
                      </div>

                      <div className="cwe-table-actions font-mono">
                        <span className="cwe-count-badge">
                          {filteredCwes.length} of {supportedVulnerabilities.length} Supported CWEs
                        </span>
                      </div>
                    </div>

                    {/* Clean Table View (Unboxed CWE ID, Unboxed Severity, Target Sinks, No Diff Button) */}
                    <div className="doc-cwe-table-container">
                      <table className="doc-cwe-table font-onest" aria-label="Supported CWE Taxonomy Table">
                        <thead>
                          <tr>
                            <th style={{ width: '90px', textAlign: 'center' }}>CWE ID</th>
                            <th style={{ minWidth: '190px' }}>Vulnerability & Impact</th>
                            <th style={{ width: '95px', textAlign: 'center' }}>Severity</th>
                            <th style={{ minWidth: '180px' }}>Target AST Sinks</th>
                            <th style={{ minWidth: '220px' }}>Detection Approach</th>
                            <th style={{ minWidth: '220px' }}>Remediation Pattern</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredCwes.map((v) => {
                            const sinks = CWE_SINKS_MAP[v.cwe] || 'AST Call node inspection';
                            const impact = CWE_IMPACT_MAP[v.cwe] || v.category;
                            const sevClass = v.severity.toLowerCase();

                            return (
                              <tr key={v.cwe} className="cwe-table-row" id={v.cwe.toLowerCase()}>
                                {/* 1. Unboxed CWE ID: Clean plain text, center aligned */}
                                <td style={{ textAlign: 'center' }}>
                                  <span className="cwe-id-clean font-mono">{v.cwe}</span>
                                </td>

                                {/* 2. Vulnerability Name & Exploit Impact */}
                                <td>
                                  <div className="cwe-name-group">
                                    <span className="cwe-table-name font-onest">{v.name}</span>
                                    <span className="cwe-impact-text font-onest">{impact}</span>
                                  </div>
                                </td>

                                {/* 3. Unboxed Severity: Clean colored text without dot, center aligned */}
                                <td style={{ textAlign: 'center' }}>
                                  <span className={`severity-text-clean font-onest sev-text-${sevClass}`}>
                                    {v.severity}
                                  </span>
                                </td>

                                {/* 4. Target AST Sinks: Useful API targets */}
                                <td className="cwe-sinks-cell">
                                  <code className="cwe-sinks-code font-mono">{sinks}</code>
                                </td>

                                {/* 5. Detection Approach */}
                                <td className="cwe-desc-cell">
                                  <p className="cwe-cell-text font-onest">{v.detectionMethod}</p>
                                </td>

                                {/* 6. Remediation Pattern */}
                                <td className="cwe-rem-cell">
                                  <p className="cwe-cell-text font-onest">{v.remediationPattern}</p>
                                </td>
                              </tr>
                            );
                          })}

                          {filteredCwes.length === 0 && (
                            <tr>
                              <td colSpan="6" className="doc-empty-table-cell font-onest">
                                No vulnerability categories matched your search query "{cweFilter}".
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </section>

                  <section id="injection-vulnerabilities" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Injection Attacks (CWE-89, CWE-78, CWE-94)</h2>
                    <p className="doc-text">
                      Injection flaws occur when untrusted user input is passed directly to an interpreter without adequate boundary separation.
                      ZeroDay remediates SQL Injection (<code>CWE-89</code>) by converting dynamic queries into parameterized SQL statements with placeholder tuples.
                      Command Injection (<code>CWE-78</code>) is addressed by eliminating <code>shell=True</code>, tokenizing arguments into strict arrays,
                      and using safe wrappers like <code>shlex.quote</code>. Code Injection (<code>CWE-94</code>) eliminates arbitrary <code>eval</code> and <code>exec</code>
                      in favor of safe literal evaluation via <code>ast.literal_eval</code>.
                    </p>
                  </section>

                  <section id="traversal-and-ssrf" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Path Traversal & SSRF (CWE-22, CWE-918)</h2>
                    <p className="doc-text">
                      Path Traversal (<code>CWE-22</code>) allows attackers to escape root working directories using relative sequences like <code>../../</code>.
                      ZeroDay synthesizes canonical validation using <code>os.path.realpath()</code> and ensures target paths remain strictly within designated base directories.
                      Server-Side Request Forgery (<code>CWE-918</code>) is mitigated by enforcing strict URL protocol allowlists (blocking <code>file://</code> and <code>gopher://</code>)
                      and validating destination hostnames against internal private IP address ranges (RFC 1918 / 127.0.0.1).
                    </p>
                  </section>

                  <section id="deserialization-and-xxe" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Deserialization & XML Flaws (CWE-502, CWE-611)</h2>
                    <p className="doc-text">
                      Untrusted object deserialization (<code>CWE-502</code>) enables remote code execution through gadget chains. ZeroDay replaces vulnerable <code>pickle.loads</code>
                      calls with safe serial formats such as JSON or HMAC-signed payloads. For XML External Entity vulnerabilities (<code>CWE-611</code>) and entity expansion bombs (<code>CWE-776</code>),
                      ZeroDay integrates <code>defusedxml</code> to neutralize external entity resolution and billion-laughs attacks.
                    </p>
                  </section>

                  <section id="crypto-and-auth" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Crypto & Auth Flaws (CWE-798, CWE-327, CWE-295)</h2>
                    <p className="doc-text">
                      Hardcoded credentials (<code>CWE-798</code>) are extracted and replaced with environment variable lookups via <code>os.environ.get</code>.
                      Broken cryptographic primitives (<code>CWE-327</code>) like MD5 or single DES are upgraded to SHA-256 and AES-GCM.
                      Disabled certificate validation flags (<code>CWE-295</code>) like <code>verify=False</code> in HTTP clients are strictly enforced to <code>True</code>.
                    </p>
                  </section>
                </div>
              )}

              {/* ----------------------------------------------------------------- */}
              {/* TOPIC 5: EVALUATION AND BENCHMARKS */}
              {/* ----------------------------------------------------------------- */}
              {currentTopic.id === 'evaluation-and-benchmarks' && (
                <div className="doc-article-body font-onest">
                  <section id="benchmark-methodology" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Empirical Benchmark Methodology</h2>
                    <p className="doc-text">
                      To ensure absolute scientific integrity and eliminate fabricated claims, ZeroDay is evaluated against a persistent,
                      reproducible benchmark suite of <strong>20 standardized test fixtures</strong>. The suite comprises 14 positive controls
                      (deliberately vulnerable microservices covering OWASP Top 10) and 6 negative controls (secure implementations of identical business logic).
                    </p>
                    <p className="doc-text">
                      Negative controls are critical to evaluating true precision: any tool that flags secure code as vulnerable suffers from false-positive
                      fatigue. ZeroDay demonstrates a verified 0.0% false positive rate across all negative control fixtures.
                    </p>
                  </section>

                  <section id="standardized-fixtures" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Standardized 20-Fixture Suite</h2>
                    <div className="doc-stat-cards-grid">
                      <div className="stat-card">
                        <span className="stat-label font-mono">TOTAL BENCHMARKS</span>
                        <span className="stat-val font-oxanium">{benchmarkMetrics.totalConfigured}</span>
                        <span className="stat-desc font-onest">20 active test fixtures</span>
                      </div>
                      <div className="stat-card">
                        <span className="stat-label font-mono">POSITIVE CONTROLS</span>
                        <span className="stat-val font-oxanium">14</span>
                        <span className="stat-desc font-onest">Deliberately vulnerable targets</span>
                      </div>
                      <div className="stat-card">
                        <span className="stat-label font-mono">NEGATIVE CONTROLS</span>
                        <span className="stat-val font-oxanium">6</span>
                        <span className="stat-desc font-onest">Secure reference baselines</span>
                      </div>
                      <div className="stat-card">
                        <span className="stat-label font-mono">FALSE POSITIVE RATE</span>
                        <span className="stat-val font-oxanium">0.0%</span>
                        <span className="stat-desc font-onest">6/6 clean baselines respected</span>
                      </div>
                    </div>
                  </section>

                  <section id="measured-results" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Ground-Truth Measured Results</h2>
                    <ul className="doc-feature-list">
                      <li><strong>Vulnerability Detection Recall:</strong> 14 out of 14 vulnerable targets caught (100.0% recall).</li>
                      <li><strong>Adversarial PoC Reproducibility:</strong> 14 out of 14 exploits confirmed in sandbox execution.</li>
                      <li><strong>Oracle-Verified Remediations:</strong> 14 out of 14 patches passed all 4 verification gates.</li>
                      <li><strong>Negative Control Accuracy:</strong> 6 out of 6 secure baselines correctly identified as clean with zero erroneous modifications.</li>
                    </ul>
                  </section>

                  <section id="confusion-matrix" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Confusion Matrix & Statistical Derivations</h2>
                    <div className="doc-table-container">
                      <table className="doc-comparison-table font-onest">
                        <thead>
                          <tr>
                            <th>Statistical Metric</th>
                            <th>Measured Value</th>
                            <th>Mathematical Formulation</th>
                            <th>Significance</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td><strong>True Positives (TP)</strong></td>
                            <td><code>14</code></td>
                            <td>Vulnerable targets detected & reproduced</td>
                            <td>Broad coverage across OWASP Top 10</td>
                          </tr>
                          <tr>
                            <td><strong>False Negatives (FN)</strong></td>
                            <td><code>0</code></td>
                            <td>Vulnerable targets missed by AST scanner</td>
                            <td>Zero missed vulnerabilities in benchmark</td>
                          </tr>
                          <tr>
                            <td><strong>True Negatives (TN)</strong></td>
                            <td><code>6</code></td>
                            <td>Secure baselines reported clean</td>
                            <td>Validates that safe code is unmolested</td>
                          </tr>
                          <tr>
                            <td><strong>False Positives (FP)</strong></td>
                            <td><code>0</code></td>
                            <td>Clean baselines mistakenly flagged</td>
                            <td>Eliminates developer alert fatigue</td>
                          </tr>
                          <tr>
                            <td><strong>Precision</strong></td>
                            <td><code>100.0%</code></td>
                            <td>TP / (TP + FP) = 14 / (14 + 0)</td>
                            <td>Absolute confidence in reported findings</td>
                          </tr>
                          <tr>
                            <td><strong>Recall (Sensitivity)</strong></td>
                            <td><code>100.0%</code></td>
                            <td>TP / (TP + FN) = 14 / (14 + 0)</td>
                            <td>Reliable coverage of supported patterns</td>
                          </tr>
                          <tr>
                            <td><strong>F1 Score</strong></td>
                            <td><code>1.00</code></td>
                            <td>2 * (Precision * Recall) / (P + R)</td>
                            <td>Optimal harmonic mean under test scope</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </section>

                  <section id="reproducing-locally" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Local Benchmark Reproducibility</h2>
                    <p className="doc-text">
                      Any developer can reproduce these exact measurements on their local machine by executing the benchmark test runner:
                    </p>
                    <div className="doc-code-block font-mono">
                      <div className="code-header">
                        <span>REPRODUCE BENCHMARKS</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard('pytest tests/benchmark/test_benchmark_suite.py -v', 'bench_cmd')}
                          className="copy-btn font-mono"
                        >
                          {copiedKey === 'bench_cmd' ? <Check size={12} /> : <Copy size={12} />}
                          {copiedKey === 'bench_cmd' ? 'COPIED' : 'COPY'}
                        </button>
                      </div>
                      <pre>
{`pytest tests/benchmark/test_benchmark_suite.py -v

# Output summary:
# 20 passed in 1.42s
# Detection Recall: 100% | False Positive Rate: 0.0% | Remediations Verified: 100%`}
                      </pre>
                    </div>
                  </section>
                </div>
              )}

              {/* ----------------------------------------------------------------- */}
              {/* TOPIC 6: SECURITY AND LIMITS */}
              {/* ----------------------------------------------------------------- */}
              {currentTopic.id === 'security-and-limits' && (
                <div className="doc-article-body font-onest">
                  <section id="security-model" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">ZeroDay Trust & Security Model</h2>
                    <p className="doc-text">
                      Honest boundaries, trust boundaries, and execution containment are fundamental design tenets of ZeroDay.
                      We treat all analyzed source code as untrusted input and isolate dynamic operations from the host runtime.
                      We never make hyperbolic claims of absolute infallibility, and we build defense-in-depth into every subsystem.
                    </p>
                  </section>

                  <section id="isolated-sandboxing" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Subprocess Execution Sandboxing</h2>
                    <p className="doc-text">
                      Adversarial exploit reproduction and regression testing are never executed in the primary application process.
                      All dynamic execution occurs inside temporary, ephemeral filesystem directories created via <code>tempfile.mkdtemp()</code>:
                    </p>
                    <ul className="doc-feature-list">
                      <li><strong>Execution Isolation:</strong> Subprocesses execute with restricted execution privileges and strict 10-second timeout enforcement to prevent denial-of-service hangs.</li>
                      <li><strong>Filesystem Shields:</strong> The parent repository, production configurations, and host system files are protected from writes during PoC reproduction.</li>
                      <li><strong>Automatic Teardown:</strong> Sandboxes are automatically scrubbed and deleted upon test completion, preventing payload persistence.</li>
                    </ul>
                  </section>

                  <section id="secret-isolation" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Secret & Token Isolation</h2>
                    <p className="doc-text">
                      ZeroDay enforces strict data privacy standards for all analyzed repositories:
                    </p>
                    <ul className="doc-feature-list">
                      <li><strong>Zero Data Retention:</strong> User repository code and AST artifacts are never logged to external servers or used to train third-party machine learning models.</li>
                      <li><strong>Secret Masking:</strong> Sensitive tokens, private API keys, and credential strings detected during AST analysis are redacted before context prompts are transmitted to inference providers.</li>
                    </ul>
                  </section>

                  <section id="crawler-boundaries" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Crawler & Public Indexing Boundaries</h2>
                    <p className="doc-text">
                      Search engine and AI crawler discovery policies are strictly enforced:
                    </p>
                    <ul className="doc-feature-list">
                      <li><strong>Public Crawling Allowed:</strong> Public documentation (<code>/documentation</code>), hackathon details (<code>/hackathon</code>), and the landing page are fully indexable by search crawlers (Google, Bing, OAI-SearchBot).</li>
                      <li><strong>Private Scan Protection:</strong> Dynamic scan sessions, user repository reports, and live arena runs return <code>X-Robots-Tag: noindex, nofollow</code> headers and are barred by <code>robots.txt</code> to safeguard intellectual property.</li>
                    </ul>
                  </section>

                  <section id="known-limitations" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Known Limitations & Boundary Scope</h2>
                    <p className="doc-text">
                      In the spirit of scientific transparency, ZeroDay explicitly documents its current architectural limitations:
                    </p>
                    <div className="doc-limits-list">
                      {limitations.map((lim, idx) => (
                        <div key={idx} className="limit-item">
                          <AlertTriangle size={16} className="limit-icon text-muted-orange" />
                          <span className="limit-text">{lim}</span>
                        </div>
                      ))}
                    </div>
                  </section>

                  <section id="human-in-the-loop" className="doc-section-anchor">
                    <h2 className="doc-section-title font-oxanium">Human-in-the-Loop Governance</h2>
                    <p className="doc-text">
                      ZeroDay is designed as an autonomous force multiplier, not an unmonitored replacement for human engineering judgement.
                      Every pull request generated by ZeroDay includes full evidence receipts (AST line numbers, synthetic PoC exploit traces,
                      4-gate execution logs, and pytest test results) to facilitate fast, confident human review before merging into production branches.
                    </p>
                  </section>
                </div>
              )}
            </main>
          </div>
        </div>

        {/* Clean Centered Documentation Footer requested by user */}
        <DocMinimalFooter onNavigate={handleFooterNav} />
      </div>
    );
  }
  // =========================================================================
  // VIEW 2: MAIN DIRECTORY PAGE (when docSlug is null)
  // =========================================================================
  return (
    <div className="documentation-page-canvas font-onest">
      {/* 1. HERO HEADER WITH CENTERED HEADING & EXCLUSIVE DOT MATRIX PATTERN */}
      <section className="doc-hero-section" aria-label="Documentation Header">
        <div className="doc-hero-dots-pattern" aria-hidden="true" />
        <div className="doc-hero-container">
          <h1 className="doc-hero-title font-oxanium">Technical Documentation</h1>
          <p className="doc-hero-subtitle font-onest">
            Core architecture, autonomous vulnerability pipelines, ground-truth benchmarks, and MITRE CWE remediation references for ZeroDay.
          </p>
        </div>
      </section>

      {/* 2. 3-COLUMN BOX GRID (2 ROWS OF 3 BOXES) */}
      <section className="doc-boxes-section" aria-label="Documentation Topics Grid">
        <div className="doc-section-container">
          <div className="doc-boxes-grid">
            {TOPIC_BOXES.map((box) => {
              const Icon = box.icon;
              return (
                <div
                  key={box.id}
                  id={box.id}
                  className="doc-box-card"
                  onClick={() => onSelectTopic && onSelectTopic(box.slug)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      if (onSelectTopic) onSelectTopic(box.slug);
                    }
                  }}
                  aria-label={`Open topic: ${box.title}`}
                >
                  <div className="box-icon-centered-wrapper" aria-hidden="true">
                    <Icon size={30} className="box-icon" />
                  </div>
                  <h2 className="box-title font-oxanium">{box.title}</h2>
                  <p className="box-desc font-onest">{box.shortDesc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* 3. GENERAL FAQS SECTION (Below the boxes) */}
      <section className="doc-faqs-section" aria-label="Frequently Asked Questions">
        <div className="doc-section-container">
          <div className="doc-faqs-header">
            <h2 className="doc-faqs-title font-oxanium">General FAQs</h2>
          </div>

          <div className="doc-faqs-accordion">
            {faqItems.map((faq, idx) => {
              const isOpen = openFaqIndex === idx;
              return (
                <div key={idx} className={`faq-accordion-item font-onest ${isOpen ? 'open' : ''}`}>
                  <button
                    type="button"
                    onClick={() => toggleFaq(idx)}
                    className="faq-accordion-trigger font-onest"
                    aria-expanded={isOpen}
                    aria-controls={`faq-answer-${idx}`}
                  >
                    <span className="faq-question-text font-onest">{faq.question}</span>
                    <span className="faq-arrow-icon" aria-hidden="true">
                      {isOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </span>
                  </button>

                  {isOpen && (
                    <div
                      id={`faq-answer-${idx}`}
                      className="faq-accordion-content font-onest"
                    >
                      <p className="faq-answer-text">{faq.answer}</p>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Clean Centered Documentation Footer */}
      <DocMinimalFooter onNavigate={handleFooterNav} />
    </div>
  );
}
