import React from 'react';
import { Coffee } from 'lucide-react';

function GithubIcon({ size = 18 }) {
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
      aria-hidden="true"
    >
      <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
    </svg>
  );
}

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

export default function Footer({ onNavigate }) {
  const handleNav = (view, e) => {
    if (onNavigate) {
      e.preventDefault();
      onNavigate(view, e);
    }
  };

  return (
    <footer className="app-footer" role="contentinfo">
      <div className="footer-container">
        {/* Main Editorial Grid: Left Brand & Hackathon Pill / Right Platform & Tech Stack */}
        <div className="footer-editorial-grid">
          {/* Left Column: ZERODAY Brand + Badge Pill + Description */}
          <div className="footer-left-brand-block">
            <div className="footer-brand-header-row">
              <span className="footer-zeroday-logo font-oxanium">ZERODAY</span>
              <div
                className="footer-hackathon-pill"
                aria-label="Nebius x NVIDIA Global AI Hackathon 2026"
              >
                <ChipIcon size={14} className="badge-chip-icon" />
                <span className="brand-nebius font-oxanium">NEBIUS</span>
                <span className="brand-x font-oxanium">x</span>
                <span className="brand-nvidia font-oxanium">NVIDIA</span>
                <span className="brand-event font-oxanium">GLOBAL AI HACKATHON 2026</span>
              </div>
            </div>

            <p className="footer-zeroday-desc font-onest">
              Autonomous, self-healing cybersecurity infrastructure that finds vulnerabilities,
              verifies exploits in isolated sandboxes, and authors verified patches with zero human
              lag.
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
                    onClick={(e) => handleNav('benchmarks', e)}
                    className="footer-nav-link link-platform"
                  >
                    Benchmarks
                  </a>
                </li>
                <li>
                  <a
                    href="/documentation"
                    onClick={(e) => handleNav('documentation', e)}
                    className="footer-nav-link link-platform"
                  >
                    Documentation
                  </a>
                </li>
                <li>
                  <a
                    href="/hackathon"
                    onClick={(e) => handleNav('hackathon', e)}
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
  );
}
