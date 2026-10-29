import React, { useState } from 'react';
import { Menu, X, Settings } from 'lucide-react';

export default function Navbar({
  currentView,
  setCurrentView,
  openConfigModal,
}) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const closeMobileMenu = () => setMobileMenuOpen(false);

  const handleNavClick = (hash) => {
    closeMobileMenu();
    if (currentView !== 'landing') {
      setCurrentView('landing');
      setTimeout(() => {
        const el = document.querySelector(hash);
        if (el) el.scrollIntoView({ behavior: 'smooth' });
      }, 50);
    }
  };

  return (
    <header className="app-nav" role="banner">
      <div className="nav-container">
        {/* Left: ZeroDay Text Logo / Wordmark */}
        <div className="nav-left">
          <div
            className="brand-wordmark-link"
            onClick={(e) => { setCurrentView('landing', e); closeMobileMenu(); }}
            style={{ cursor: 'pointer', display: 'flex', alignItems: 'center' }}
            title="ZeroDay Home"
            tabIndex={0}
            role="button"
            onKeyDown={(e) => { if (e.key === 'Enter') setCurrentView('landing', e); }}
          >
            <span className="brand-zeroday-text font-oxanium">ZERODAY</span>
          </div>
        </div>

        {/* Right Side: Desktop Nav Items & Mobile Menu Trigger */}
        <div className="nav-right">
          {/* Desktop Nav Items - preserved exactly as on landing page */}
          <nav className="nav-items-group desktop-only-nav" aria-label="Main Navigation">
            {currentView !== 'landing' && (
              <button
                type="button"
                onClick={(e) => {
                  e.preventDefault();
                  setCurrentView('landing', e);
                }}
                className="nav-link font-onest"
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
                id="nav-home-btn"
              >
                Home
              </button>
            )}
            <a
              href="#architecture"
              onClick={(e) => {
                if (currentView !== 'landing') {
                  e.preventDefault();
                  handleNavClick('#architecture');
                }
              }}
              className="nav-link font-onest"
            >
              Architecture
            </a>
            <a
              href="#how-it-works"
              onClick={(e) => {
                if (currentView !== 'landing') {
                  e.preventDefault();
                  handleNavClick('#how-it-works');
                }
              }}
              className="nav-link font-onest"
            >
              Pipeline Stages
            </a>
            <button
              type="button"
              onClick={(e) => {
                e.preventDefault();
                setCurrentView('benchmarks', e);
              }}
              className={`nav-link font-onest ${currentView === 'benchmarks' ? 'active' : ''}`}
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
            >
              Benchmarks
            </button>

            {/* Operator Settings action: ON /arena ONLY */}
            {currentView === 'arena' && (
              <button
                type="button"
                onClick={openConfigModal}
                className="nav-btn-add-key font-onest"
                title="Operator & API Settings"
                id="nav-settings-btn"
              >
                <Settings size={13} aria-hidden="true" />
                <span>Settings</span>
              </button>
            )}

            {/* ONLY rendered on landing page; removed on /arena */}
            {currentView === 'landing' && (
              <button
                onClick={(e) => setCurrentView('arena', e)}
                className="nav-btn-start-arena font-onest"
                title="Launch Cyber Arena"
                id="nav-start-arena-btn"
              >
                <span>START ARENA</span>
                <span className="nav-btn-arrow">&rarr;</span>
              </button>
            )}
          </nav>

          {/* Mobile Hamburger Toggle */}
          <button
            className="mobile-nav-toggle"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={mobileMenuOpen}
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer Menu */}
      {mobileMenuOpen && (
        <div className="mobile-nav-drawer" role="dialog" aria-label="Mobile Navigation Menu">
          <nav className="mobile-nav-links">
            {currentView !== 'landing' && (
              <button
                type="button"
                className="mobile-nav-link font-onest"
                onClick={(e) => {
                  setCurrentView('landing', e);
                  closeMobileMenu();
                }}
                style={{ background: 'none', border: 'none', textAlign: 'left', cursor: 'pointer', padding: '10px 0' }}
              >
                Home
              </button>
            )}
            <a
              href="#architecture"
              className="mobile-nav-link font-onest"
              onClick={(e) => {
                if (currentView !== 'landing') {
                  e.preventDefault();
                  handleNavClick('#architecture');
                } else {
                  closeMobileMenu();
                }
              }}
            >
              Architecture
            </a>
            <a
              href="#how-it-works"
              className="mobile-nav-link font-onest"
              onClick={(e) => {
                if (currentView !== 'landing') {
                  e.preventDefault();
                  handleNavClick('#how-it-works');
                } else {
                  closeMobileMenu();
                }
              }}
            >
              Pipeline Stages
            </a>
            <button
              className="mobile-nav-link font-onest"
              onClick={(e) => {
                setCurrentView('benchmarks', e);
                closeMobileMenu();
              }}
              style={{ background: 'none', border: 'none', textAlign: 'left', cursor: 'pointer', padding: '10px 0' }}
            >
              Benchmarks
            </button>

            {currentView === 'arena' && (
              <button
                onClick={() => { openConfigModal(); closeMobileMenu(); }}
                className="mobile-drawer-btn-key font-onest"
                id="mobile-nav-settings-btn"
              >
                <Settings size={14} aria-hidden="true" />
                <span>Settings</span>
              </button>
            )}

            {currentView === 'landing' && (
              <button
                onClick={(e) => { setCurrentView('arena', e); closeMobileMenu(); }}
                className="mobile-drawer-cta font-onest"
              >
                <span>START THE ARENA &rarr;</span>
              </button>
            )}
          </nav>
        </div>
      )}
    </header>
  );
}
