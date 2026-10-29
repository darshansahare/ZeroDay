/**
 * ZeroDay SEO, AEO, GEO & Social Metadata Engine
 * Handles dynamic route metadata updates, Open Graph, Twitter Cards,
 * and Schema.org JSON-LD structured data for search and AI answer engines.
 */

import { PROJECT_KNOWLEDGE } from '../config/projectKnowledge';

export const SITE_ORIGIN =
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_SITE_URL) ||
  (typeof window !== 'undefined' && window.location.origin ? window.location.origin : 'https://zeroday.dev');

/**
 * Route metadata specifications
 */
export const ROUTE_METADATA = {
  landing: {
    title: 'ZeroDay',
    ogTitle: 'ZeroDay — Autonomous Code Vulnerability Detection & Remediation',
    description:
      'Analyze code for security vulnerabilities, inspect evidence-backed findings, and validate proposed fixes with ZeroDay\'s AI-assisted security workflow.',
    path: '/',
    robots: 'index, follow',
    isPublic: true,
  },
  arena: {
    title: 'Target Selection | ZeroDay',
    ogTitle: 'Target Selection — ZeroDay Security Arena',
    description:
      'Select a target repository or configure vulnerability test applications for autonomous security evaluation and exploit analysis.',
    path: '/arena',
    robots: 'index, follow',
    isPublic: true,
  },
  benchmarks: {
    title: 'Security Benchmarks | ZeroDay',
    ogTitle: 'Security Benchmarks — ZeroDay Arena Suite',
    description:
      'Explore verified vulnerability benchmarks, reproducible exploit test suites, and autonomous remediation evidence reports across OWASP Top 10 categories.',
    path: '/benchmarks',
    robots: 'index, follow',
    isPublic: true,
  },
  documentation: {
    title: 'ZeroDay Documentation | Architecture, CWEs, Benchmarks & Setup',
    ogTitle: 'ZeroDay Documentation — Autonomous Vulnerability Detection & Remediation',
    description:
      'Comprehensive technical documentation for ZeroDay: 6-stage autonomous loop, 14 supported CWE categories, empirical benchmark methodology, and developer setup.',
    path: '/documentation',
    robots: 'index, follow',
    isPublic: true,
  },
  docs: {
    title: 'ZeroDay Documentation | Architecture, CWEs, Benchmarks & Setup',
    ogTitle: 'ZeroDay Documentation — Autonomous Vulnerability Detection & Remediation',
    description:
      'Comprehensive technical documentation for ZeroDay: 6-stage autonomous loop, 14 supported CWE categories, empirical benchmark methodology, and developer setup.',
    path: '/documentation',
    robots: 'index, follow',
    isPublic: true,
  },
  hackathon: {
    title: 'ZeroDay | AI-Assisted Security Tool — Nebius × NVIDIA Global AI Hackathon 2026',
    ogTitle: 'ZeroDay — Nebius × NVIDIA Global AI Hackathon 2026',
    description:
      'Explore ZeroDay, an AI-assisted vulnerability detection and remediation project built with NVIDIA Nemotron and Nebius Token Factory for the Nebius × NVIDIA Global AI Hackathon 2026.',
    path: '/hackathon',
    robots: 'index, follow',
    isPublic: true,
  },
  'benchmark-run': {
    title: 'Benchmark Inspection | ZeroDay',
    ogTitle: 'Benchmark Case Inspection — ZeroDay',
    description:
      'Inspect standardized vulnerability telemetry, AST static scan findings, and autonomous patch verification evidence.',
    path: '/benchmarks',
    robots: 'noindex, follow',
    isPublic: true,
  },
  'arena-run': {
    // Private/user-specific analysis workspace
    // Strictly protects source code, credentials, and vulnerability details from indexing
    title: 'Remediation Workspace | ZeroDay',
    ogTitle: 'Remediation Workspace — ZeroDay Arena',
    description: 'Autonomous adversarial analysis workspace and verification engine.',
    path: '/arena',
    robots: 'noindex, nofollow',
    isPublic: false,
  },
  'not-found': {
    title: '404 Page Not Found',
    ogTitle: '404 Page Not Found — ZeroDay',
    description: 'The resource you are looking for is not available at this address.',
    path: '/404',
    robots: 'noindex, nofollow',
    isPublic: false,
  },
};

/**
 * Resolve metadata for current route state
 */
export function getRouteMetadata(routeState) {
  if (!routeState || !routeState.view) {
    return ROUTE_METADATA.landing;
  }

  if (routeState.view === 'documentation' || routeState.view === 'docs') {
    if (routeState.runId) {
      const topicTitles = {
        'what-is-zeroday': 'What is ZeroDay?',
        'how-it-works': 'How it Works',
        'installing-zeroday': 'Installing ZeroDay',
        'supported-cwes': 'Supported CWEs',
        'evaluation-and-benchmarks': 'Evaluation and benchmarks',
        'security-and-limits': 'Security and Limits',
      };
      const title = topicTitles[routeState.runId] || 'Technical Documentation';
      return {
        ...ROUTE_METADATA.documentation,
        title: `${title} | ZeroDay Documentation`,
        ogTitle: `${title} — ZeroDay Technical Documentation`,
        path: `/documentation/${encodeURIComponent(routeState.runId)}`,
      };
    }
    return ROUTE_METADATA.documentation;
  }

  if (routeState.view === 'arena-run') {
    if (routeState.isBenchmark) {
      return {
        ...ROUTE_METADATA['benchmark-run'],
        path: routeState.runId ? `/benchmarks/${encodeURIComponent(routeState.runId)}` : '/benchmarks',
      };
    }
    return {
      ...ROUTE_METADATA['arena-run'],
      path: routeState.runId ? `/arena/runs/${encodeURIComponent(routeState.runId)}` : '/arena',
    };
  }

  return ROUTE_METADATA[routeState.view] || ROUTE_METADATA['not-found'];
}

/**
 * Build Schema.org JSON-LD objects for the current view
 */
export function buildJsonLdSchema(routeState, canonicalUrl) {
  const view = routeState?.view || 'landing';
  const baseAppSchema = {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'ZeroDay',
    alternateName: 'ZeroDay Arena',
    operatingSystem: 'Cross-platform (Linux, macOS, Windows via Python 3.12+)',
    applicationCategory: 'SecurityApplication',
    description:
      'Autonomous vulnerability detection and verified remediation platform for web microservices powered by NVIDIA Nemotron on Nebius Token Factory and Tavily threat intelligence.',
    url: canonicalUrl,
    license: 'https://opensource.org/licenses/MIT',
    softwareVersion: '1.0.0',
    author: {
      '@type': 'Person',
      name: 'Darshan Sahare',
      url: 'https://github.com/darshansahare',
    },
    offers: {
      '@type': 'Offer',
      price: '0.00',
      priceCurrency: 'USD',
    },
  };

  if (view === 'documentation' || view === 'docs') {
    return {
      '@context': 'https://schema.org',
      '@graph': [
        baseAppSchema,
        {
          '@type': 'TechArticle',
          headline: 'ZeroDay Technical Documentation & Architecture Reference',
          description:
            'Reference documentation covering AST reconnaissance, NVIDIA Nemotron patch synthesis, 4-gate verification oracle, and benchmark evaluation.',
          url: canonicalUrl,
          author: {
            '@type': 'Person',
            name: 'Darshan Sahare',
          },
        },
        {
          '@type': 'FAQPage',
          mainEntity: PROJECT_KNOWLEDGE.faqItems.map((faq) => ({
            '@type': 'Question',
            name: faq.question,
            acceptedAnswer: {
              '@type': 'Answer',
              text: faq.answer,
            },
          })),
        },
        {
          '@type': 'BreadcrumbList',
          itemListElement: [
            {
              '@type': 'ListItem',
              position: 1,
              name: 'Home',
              item: `${SITE_ORIGIN}/`,
            },
            {
              '@type': 'ListItem',
              position: 2,
              name: 'Documentation',
              item: canonicalUrl,
            },
          ],
        },
      ],
    };
  }

  if (view === 'hackathon') {
    return {
      '@context': 'https://schema.org',
      '@graph': [
        baseAppSchema,
        {
          '@type': 'TechArticle',
          headline: 'ZeroDay | AI-Assisted Security Tool — Nebius × NVIDIA Global AI Hackathon 2026',
          description:
            'Official project documentation for ZeroDay submitted to the Nebius × NVIDIA Global AI Hackathon 2026 under the Coding & Agentic Engineering track.',
          url: canonicalUrl,
          author: {
            '@type': 'Person',
            name: 'Darshan Sahare',
          },
        },
        {
          '@type': 'BreadcrumbList',
          itemListElement: [
            {
              '@type': 'ListItem',
              position: 1,
              name: 'Home',
              item: `${SITE_ORIGIN}/`,
            },
            {
              '@type': 'ListItem',
              position: 2,
              name: 'Hackathon Project',
              item: canonicalUrl,
            },
          ],
        },
      ],
    };
  }

  if (view === 'benchmarks') {
    return {
      '@context': 'https://schema.org',
      '@graph': [
        baseAppSchema,
        {
          '@type': 'Dataset',
          name: 'ZeroDay Vulnerability & Clean Baseline Evaluation Benchmark Suite',
          description:
            'A suite of 20 standardized test fixtures (14 vulnerable targets across OWASP Top 10 and 6 clean baselines) evaluating detection recall, false positive rates, and verified patch rates.',
          url: canonicalUrl,
          creator: {
            '@type': 'Person',
            name: 'Darshan Sahare',
          },
        },
      ],
    };
  }

  return {
    '@context': 'https://schema.org',
    '@graph': [
      baseAppSchema,
      {
        '@type': 'WebSite',
        name: 'ZeroDay',
        url: `${SITE_ORIGIN}/`,
        description:
          'Autonomous vulnerability detection and verified remediation platform powered by NVIDIA Nemotron on Nebius Token Factory.',
      },
    ],
  };
}

/**
 * Dynamically synchronize HTML document <head> meta tags on client-side route navigation
 */
export function updateRouteMetadata(routeState) {
  if (typeof document === 'undefined') return;

  const meta = getRouteMetadata(routeState);

  // 1. Page Title
  document.title = meta.title;

  // 2. Helper to set or create meta elements
  const setMeta = (attrName, attrVal, content) => {
    let el = document.querySelector(`meta[${attrName}="${attrVal}"]`);
    if (!el) {
      el = document.createElement('meta');
      el.setAttribute(attrName, attrVal);
      document.head.appendChild(el);
    }
    el.setAttribute('content', content);
  };

  // 3. Search Engine Directives
  setMeta('name', 'description', meta.description);
  setMeta('name', 'robots', meta.robots);

  // 4. Canonical URL
  const canonicalUrl = `${SITE_ORIGIN}${meta.path}`;
  let canonicalEl = document.querySelector('link[rel="canonical"]');
  if (!canonicalEl) {
    canonicalEl = document.createElement('link');
    canonicalEl.setAttribute('rel', 'canonical');
    document.head.appendChild(canonicalEl);
  }
  canonicalEl.setAttribute('href', canonicalUrl);

  // 5. Open Graph & Social Sharing Previews (Absolute URLs)
  const imageUrl = `${SITE_ORIGIN}/og-image.png`;
  const shareTitle = meta.ogTitle || meta.title;

  setMeta('property', 'og:title', shareTitle);
  setMeta('property', 'og:description', meta.description);
  setMeta('property', 'og:type', 'website');
  setMeta('property', 'og:url', canonicalUrl);
  setMeta('property', 'og:image', imageUrl);
  setMeta('property', 'og:image:width', '1200');
  setMeta('property', 'og:image:height', '630');
  setMeta('property', 'og:image:type', 'image/png');
  setMeta('property', 'og:image:alt', 'ZeroDay — Find the flaw. Prove the fix.');
  setMeta('property', 'og:site_name', 'ZeroDay');

  // 6. Twitter / X Cards
  setMeta('name', 'twitter:card', 'summary_large_image');
  setMeta('name', 'twitter:title', shareTitle);
  setMeta('name', 'twitter:description', meta.description);
  setMeta('name', 'twitter:image', imageUrl);
  setMeta('name', 'twitter:image:alt', 'ZeroDay — Find the flaw. Prove the fix.');

  // 7. Inject / Update Schema.org JSON-LD structured data
  if (meta.isPublic) {
    const jsonLdData = buildJsonLdSchema(routeState, canonicalUrl);
    let scriptEl = document.querySelector('script#zeroday-jsonld');
    if (!scriptEl) {
      scriptEl = document.createElement('script');
      scriptEl.setAttribute('type', 'application/ld+json');
      scriptEl.setAttribute('id', 'zeroday-jsonld');
      document.head.appendChild(scriptEl);
    }
    scriptEl.textContent = JSON.stringify(jsonLdData);
  } else {
    // If route is private or 404, remove public JSON-LD to prevent indexing
    const scriptEl = document.querySelector('script#zeroday-jsonld');
    if (scriptEl && scriptEl.parentNode) {
      scriptEl.parentNode.removeChild(scriptEl);
    }
  }
}
