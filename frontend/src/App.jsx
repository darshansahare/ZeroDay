import React, { useState, useEffect, useCallback } from 'react';
import Navbar from './components/Navbar';
import LandingPage from './components/LandingPage';
import ArenaTargetSelect from './components/ArenaTargetSelect';
import ArenaRunWorkspace from './components/ArenaRunWorkspace';
import BenchmarksPage from './components/BenchmarksPage';
import DocsPage from './components/DocsPage';
import HackathonPage from './components/HackathonPage';
import NotFoundPage from './components/NotFoundPage';
import ConfigModal from './components/ConfigModal';
import { updateRouteMetadata } from './utils/seo';
import './App.css';

export default function App() {
  // Parse route from current pathname
  const parseCurrentPath = useCallback(() => {
    const path = window.location.pathname;
    if (path === '/' || path === '') {
      return { view: 'landing', runId: null, isBenchmark: false, requestedPath: path };
    }
    if (path.startsWith('/arena/runs/')) {
      const parts = path.split('/');
      const runId = parts[3] ? decodeURIComponent(parts[3]) : '';
      return { view: 'arena-run', runId, isBenchmark: false, requestedPath: path };
    }
    if (path === '/arena' || path === '/arena/') {
      return { view: 'arena', runId: null, isBenchmark: false, requestedPath: path };
    }
    if (path.startsWith('/benchmarks/')) {
      const parts = path.split('/');
      const runId = parts[2] ? decodeURIComponent(parts[2]) : '';
      return { view: 'arena-run', runId, isBenchmark: true, requestedPath: path };
    }
    if (path === '/benchmarks' || path === '/benchmarks/') {
      return { view: 'benchmarks', runId: null, isBenchmark: false, requestedPath: path };
    }
    if (
      path === '/documentation' ||
      path === '/documentation/' ||
      path.startsWith('/documentation/') ||
      path === '/docs' ||
      path === '/docs/' ||
      path.startsWith('/docs/')
    ) {
      const parts = path.split('/').filter(Boolean);
      // e.g. ['documentation', 'what-is-zeroday']
      const topicSlug = parts.length > 1 ? decodeURIComponent(parts[1]) : null;
      const target = topicSlug ? `/documentation/${encodeURIComponent(topicSlug)}` : '/documentation';
      return { view: 'documentation', runId: topicSlug, isBenchmark: false, requestedPath: target };
    }
    if (path === '/hackathon' || path === '/hackathon/') {
      return { view: 'hackathon', runId: null, isBenchmark: false, requestedPath: path };
    }
    return { view: 'not-found', runId: null, isBenchmark: false, requestedPath: path };
  }, []);

  const [routeState, setRouteState] = useState(parseCurrentPath);
  const [isConfigModalOpen, setIsConfigModalOpen] = useState(false);
  const [systemHealth, setSystemHealth] = useState(null);
  const [runtimeConfig, setRuntimeConfig] = useState(null);

  // Synchronized route navigation with smooth transition
  const navigateTo = useCallback((view, runId = null, isBenchmark = false, initialData = null) => {
    let targetPath = '/';
    if (view === 'arena') targetPath = '/arena';
    else if (view === 'benchmarks') targetPath = '/benchmarks';
    else if (view === 'documentation' || view === 'docs') targetPath = runId ? `/documentation/${encodeURIComponent(runId)}` : '/documentation';
    else if (view === 'hackathon') targetPath = '/hackathon';
    else if (view === 'arena-run' && runId) {
      targetPath = isBenchmark ? `/benchmarks/${encodeURIComponent(runId)}` : `/arena/runs/${encodeURIComponent(runId)}`;
    }

    setRouteState({ view, runId, isBenchmark, requestedPath: targetPath, initialData });
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    if (window.location.pathname !== targetPath) {
      window.history.pushState(null, '', targetPath);
    }
  }, []);

  // Back action with history length check & sensible fallback to landing
  const handleGoBack = useCallback(() => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      navigateTo('landing');
    }
  }, [navigateTo]);

  // Listen to browser Back/Forward buttons (instant navigation without transition)
  useEffect(() => {
    const handlePopState = () => {
      setRouteState(parseCurrentPath());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, [parseCurrentPath]);

  // Synchronize dynamic SEO, Open Graph, Twitter, and canonical metadata on route change
  useEffect(() => {
    updateRouteMetadata(routeState);
  }, [routeState]);

  // Fetch system health and config status
  const fetchHealthAndConfig = useCallback(async () => {
    try {
      const [healthRes, configRes] = await Promise.all([
        fetch('/api/health').catch(() => null),
        fetch('/api/config').catch(() => null),
      ]);

      if (healthRes && healthRes.ok) {
        const healthData = await healthRes.json();
        setSystemHealth(healthData);
      }
      if (configRes && configRes.ok) {
        const configData = await configRes.json();
        setRuntimeConfig(configData);
      }
    } catch (err) {
      console.error('Error fetching backend status:', err);
    }
  }, []);

  useEffect(() => {
    fetchHealthAndConfig();
  }, [fetchHealthAndConfig]);

  // Pre-fetch benchmark suite data so transitions to /benchmarks are instantaneous and smooth
  useEffect(() => {
    fetch('/api/benchmarks')
      .then((res) => (res.ok ? res.json() : null))
      .then((benchData) => {
        if (benchData) {
          try {
            sessionStorage.setItem('zda_benchmarks_cache', JSON.stringify(benchData));
          } catch {
            /* ignore */
          }
        }
      })
      .catch(() => { });
  }, []);

  return (
    <div className="app-container">
      {/* Shared Navbar across all views except 404 page */}
      {routeState.view !== 'not-found' && (
        <Navbar
          currentView={routeState.view}
          setCurrentView={(v, e) => navigateTo(v, null, false, e)}
          openConfigModal={() => setIsConfigModalOpen(true)}
        />
      )}

      {/* Screen Routing with smooth view transition */}
      <main key={routeState.view} className={`view-transition-wrapper view-${routeState.view}`}>
        {routeState.view === 'landing' && (
          <LandingPage
            setCurrentView={(v, e) => navigateTo(v, null, false, e)}
          />
        )}

        {routeState.view === 'arena' && (
          <ArenaTargetSelect
            onSelectRun={(runId, initialData) => navigateTo('arena-run', runId, false, initialData)}
            openConfigModal={() => setIsConfigModalOpen(true)}
            systemHealth={systemHealth}
          />
        )}

        {routeState.view === 'benchmarks' && (
          <BenchmarksPage
            onSelectBenchmark={(id) => navigateTo('arena-run', id, true)}
            onNavigateToArena={() => navigateTo('arena', null, false)}
          />
        )}

        {routeState.view === 'arena-run' && (
          <ArenaRunWorkspace
            runId={routeState.runId}
            initialRunSummary={routeState.initialData}
            onNavigateBack={() => navigateTo(routeState.isBenchmark ? 'benchmarks' : 'arena')}
            openConfigModal={() => setIsConfigModalOpen(true)}
            runtimeConfig={runtimeConfig}
          />
        )}

        {(routeState.view === 'documentation' || routeState.view === 'docs') && (
          <DocsPage
            docSlug={routeState.runId}
            onSelectTopic={(slug) => navigateTo('documentation', slug)}
            onBackToDirectory={() => navigateTo('documentation')}
            onNavigateToArena={() => navigateTo('arena')}
            onNavigateToHackathon={() => navigateTo('hackathon')}
          />
        )}

        {routeState.view === 'hackathon' && (
          <HackathonPage
            onNavigateToArena={() => navigateTo('arena')}
            onNavigateToDocs={() => navigateTo('documentation')}
            onNavigateHome={() => navigateTo('landing')}
            onNavigateToBenchmarks={() => navigateTo('benchmarks')}
          />
        )}

        {routeState.view === 'not-found' && (
          <NotFoundPage
            onNavigateHome={() => navigateTo('landing')}
          />
        )}
      </main>

      {/* Global Config Modal */}
      <ConfigModal
        isOpen={isConfigModalOpen}
        onClose={() => setIsConfigModalOpen(false)}
        runtimeConfig={runtimeConfig}
        onConfigUpdated={(newCfg) => {
          setRuntimeConfig(newCfg);
          fetchHealthAndConfig();
        }}
      />

    </div>
  );
}
