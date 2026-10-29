/**
 * ZeroDay Project Knowledge Source of Truth
 * Maintainable public-facing knowledge base for AEO, GEO, AI answer engines, and documentation.
 * All data here reflects verified repository capabilities, benchmarks, and model integrations.
 */

export const PROJECT_KNOWLEDGE = {
  brand: {
    name: 'ZeroDay',
    legalName: 'ZeroDay Autonomous Security Platform',
    tagline: 'Find the flaw. Prove the fix.',
    summary:
      'Autonomous vulnerability detection and verified remediation platform for Python web applications. Combines static AST sink reconnaissance, isolated subprocess exploit reproduction, NVIDIA Nemotron patch synthesis via Nebius Token Factory, and a deterministic 4-gate verification oracle.',
    author: 'Darshan Sahare',
    githubProfile: 'https://github.com/darshansahare',
    repositoryUrl: 'https://github.com/darshansahare/ZeroDay',
    canonicalDomain: 'https://zeroday.dev',
    license: 'MIT',
    category: 'Developer Security Tool / Autonomous Cyber Defense',
  },

  hackathon: {
    eventName: 'Nebius × NVIDIA Global AI Hackathon 2026',
    dates: 'February - March 2026',
    track: 'Coding & Agentic Engineering',
    challengeTheme: 'Autonomous AI Agents & Intelligent Developer Tooling',
    officialUrl: 'https://nebius.com',
    devpostUrl: 'https://nebiusglobalaihackathon.devpost.com/',
    demoVideoUrl: '', // Configurable: URL for recorded walkthrough video (if available)
    nebiusService: 'Nebius Token Factory (Inference API)',
    nebiusBaseUrl: 'https://api.tokenfactory.nebius.com/v1/',
    primaryModel: 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B',
    benchmarkModel: 'nvidia/nemotron-3-super-120b-a12b',
    searchService: 'Tavily Search API (Grounding & Threat Intelligence)',
    integrationSummary:
      'ZeroDay leverages NVIDIA Nemotron models hosted on Nebius Token Factory for targeted root-cause analysis and unified diff patch synthesis, grounded by Tavily live threat intelligence for CWE/OWASP mitigation context.',
  },

  architecture: {
    frontendStack: 'React 19 + Vite (pure JavaScript & JSX, zero TypeScript)',
    backendStack: 'Python 3.12 + FastAPI + Uvicorn + WebSockets',
    reconEngine: 'Python ast (Abstract Syntax Tree) static sink scanner',
    reproductionEngine: 'Isolated sandbox subprocess test runner with ASGI client',
    synthesisEngine: 'NVIDIA Nemotron via Nebius Token Factory (OpenAI-compatible protocol)',
    verificationEngine: 'Deterministic 4-Gate Invariant Oracle (Syntax AST, Static Delta, Exploit Replay, Regression Pytest)',
    cacheEngine: 'TokenOptimizationCache with token hashing & FinOps cost optimization',
  },

  pipelineStages: [
    {
      stage: 1,
      name: 'AST Code Reconnaissance',
      agent: 'Red Team Agent',
      description:
        'Parses Python source code into Abstract Syntax Trees, identifying unparameterized SQL execution, unsanitized path joins, and missing authorization decorators without executing untrusted code.',
    },
    {
      stage: 2,
      name: 'Threat Intelligence Grounding',
      agent: 'ZeroDay Core',
      description:
        'Queries Tavily AI Search to retrieve authoritative CWE mitigation advisories, OWASP cheat sheets, and safe coding patterns tailored to the detected sink.',
    },
    {
      stage: 3,
      name: 'Exploit Reproduction',
      agent: 'Red Team Agent',
      description:
        'Executes synthetic proof-of-concept security probes in an isolated subprocess sandbox to prove whether the vulnerability is genuinely exploitable and observe data leakage.',
    },
    {
      stage: 4,
      name: 'Nemotron Triage & Plan',
      agent: 'Blue Team Agent',
      description:
        'Invokes nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B through Nebius Token Factory, combining AST findings and threat intelligence to analyze the root cause and plan a minimal patch.',
    },
    {
      stage: 5,
      name: 'Autonomous Patch Synthesis',
      agent: 'Blue Team Agent',
      description:
        'Synthesizes a clean, standard unified diff (e.g. parameterized queries or boundary checks) adhering strictly to standard language libraries.',
    },
    {
      stage: 6,
      name: 'Independent 4-Gate Verification',
      agent: 'Verification Oracle',
      description:
        'Validates syntax compilation, verifies static sink elimination, replays the exploit to confirm rejection, and runs pytest regression suites to guarantee zero business logic regressions.',
    },
  ],

  supportedVulnerabilities: [
    {
      cwe: 'CWE-89',
      name: 'SQL Injection',
      category: 'Injection',
      severity: 'Critical',
      description:
        'Unescaped or unparameterized user input concatenated directly into SQL query strings.',
      detectionMethod: 'AST Call node inspection on execute/executemany with formatted string arguments (f-strings, % formatting, .format).',
      remediationPattern: 'Parameterized query placeholders (? or :param) with tuple argument binding.',
      safeExample: 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
      vulnerableExample: 'cursor.execute(f"SELECT * FROM users WHERE id = \'{user_id}\'")',
    },
    {
      cwe: 'CWE-22',
      name: 'Path Traversal (Arbitrary File Read)',
      category: 'Path Traversal',
      severity: 'High',
      description:
        'User-controlled path components allowing ../ sequences to traverse outside the designated file root directory.',
      detectionMethod: 'AST binary operator inspection (Path / input) combined with read_text/open calls lacking boundary verification.',
      remediationPattern: 'Path.resolve() containment check using path.is_relative_to(safe_base).',
      safeExample: 'target = (BASE_DIR / filename).resolve()\nif not target.is_relative_to(BASE_DIR.resolve()):\n    raise HTTPException(403)',
      vulnerableExample: 'target = BASE_DIR / filename\nreturn target.read_text()',
    },
    {
      cwe: 'CWE-284',
      cweAlt: 'CWE-639',
      name: 'Broken Access Control / IDOR',
      category: 'Authorization',
      severity: 'High',
      description:
        'Endpoints retrieving sensitive user data by ID without verifying that the requesting actor owns or has access to the record.',
      detectionMethod: 'AST route argument inspection detecting path parameters mapped directly to storage retrieval without tenant or session check.',
      remediationPattern: 'Enforce current_user_id authorization check before returning requested resource.',
      safeExample: 'if current_user_id != user_id:\n    raise HTTPException(403, detail="Unauthorized")\nreturn users.get(user_id)',
      vulnerableExample: 'return users.get(user_id)',
    },
    {
      cwe: 'CWE-78',
      name: 'OS Command Injection',
      category: 'Injection',
      severity: 'Critical',
      description:
        'Subprocess execution with shell=True or unescaped string command arguments passed to system shells.',
      detectionMethod: 'AST inspection of subprocess.run/Popen/call with shell=True or string concatenation.',
      remediationPattern: 'Use argument lists with shell=False and strict input validation.',
      safeExample: 'subprocess.run(["ping", "-c", "1", ip_address], shell=False, check=True)',
      vulnerableExample: 'subprocess.run(f"ping -c 1 {ip_address}", shell=True)',
    },
    {
      cwe: 'CWE-918',
      name: 'Server-Side Request Forgery (SSRF)',
      category: 'SSRF',
      severity: 'High',
      description:
        'Arbitrary outbound HTTP requests to internal IP addresses or cloud metadata endpoints (169.254.169.254).',
      detectionMethod: 'AST inspection of httpx.get/requests.get with unvalidated user-supplied destination URLs.',
      remediationPattern: 'Domain whitelist validation and private IP range blocking (10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16).',
      safeExample: 'if parsed.hostname not in ALLOWED_DOMAINS:\n    raise HTTPException(403)',
      vulnerableExample: 'httpx.get(request_url)',
    },
    {
      cwe: 'CWE-502',
      name: 'Insecure Deserialization',
      category: 'Deserialization',
      severity: 'Critical',
      description:
        'Deserializing untrusted pickle, yaml.load, or marshal payloads leading to arbitrary code execution.',
      detectionMethod: 'AST Call detection on pickle.loads, pickle.load, or yaml.load without SafeLoader.',
      remediationPattern: 'Replace binary serialization with structured JSON or yaml.safe_load.',
      safeExample: 'json.loads(payload)',
      vulnerableExample: 'pickle.loads(payload)',
    },
    {
      cwe: 'CWE-798',
      name: 'Hardcoded Credentials',
      category: 'Credentials',
      severity: 'High',
      description:
        'Plaintext API keys, database passwords, or JWT secrets embedded directly in source code.',
      detectionMethod: 'AST constant string matching on variable assignments containing SECRET, PASSWORD, API_KEY, TOKEN.',
      remediationPattern: 'Load credentials from environment variables via os.environ.',
      safeExample: 'secret_key = os.environ["SECRET_KEY"]',
      vulnerableExample: 'secret_key = "super_secret_jwt_key_12345"',
    },
    {
      cwe: 'CWE-328',
      name: 'Use of Weak Hash Algorithm',
      category: 'Cryptography',
      severity: 'Medium',
      description:
        'Cryptographic hashing with MD5 or SHA-1 for passwords or integrity signatures.',
      detectionMethod: 'AST Call detection on hashlib.md5 or hashlib.sha1.',
      remediationPattern: 'Upgrade to SHA-256/SHA-512 or Argon2/bcrypt for passwords.',
      safeExample: 'hashlib.sha256(password.encode()).hexdigest()',
      vulnerableExample: 'hashlib.md5(password.encode()).hexdigest()',
    },
    {
      cwe: 'CWE-601',
      name: 'Open Redirect',
      category: 'Redirect',
      severity: 'Medium',
      description:
        'Redirecting users to arbitrary external URLs supplied via query parameters.',
      detectionMethod: 'AST Call detection on RedirectResponse with unvalidated destination parameters.',
      remediationPattern: 'Validate target URL against relative path format or trusted domain whitelist.',
      safeExample: 'if not target_url.startswith("/") or target_url.startswith("//"):\n    target_url = "/"',
      vulnerableExample: 'return RedirectResponse(url=target_url)',
    },
    {
      cwe: 'CWE-942',
      name: 'Permissive CORS Policy',
      category: 'Access Control',
      severity: 'Medium',
      description:
        'CORS configured with allow_origins=["*"] while allow_credentials=True.',
      detectionMethod: 'AST Call detection on add_middleware(CORSMiddleware) with wildcard origins and credentials enabled.',
      remediationPattern: 'Specify explicit trusted origins instead of wildcard matching.',
      safeExample: 'allow_origins=["https://app.zeroday.dev"]',
      vulnerableExample: 'allow_origins=["*"], allow_credentials=True',
    },
    {
      cwe: 'CWE-489',
      name: 'Active Debug Endpoint in Production',
      category: 'Configuration',
      severity: 'Low',
      description:
        'Debug, profiling, or system inspection endpoints exposed in production environments.',
      detectionMethod: 'AST route detection on paths containing /debug, /trace, /internal with server environment disclosure.',
      remediationPattern: 'Gate debug endpoints behind production environment checks.',
      safeExample: 'if os.getenv("ENVIRONMENT") != "development":\n    raise HTTPException(404)',
      vulnerableExample: '@app.get("/debug/env")\ndef dump_env(): return dict(os.environ)',
    },
    {
      cwe: 'CWE-614',
      name: 'Missing Cookie Security Flags',
      category: 'Session Management',
      severity: 'Low',
      description:
        'Session cookies set without httponly=True, secure=True, or samesite="lax".',
      detectionMethod: 'AST Call detection on set_cookie with missing or false secure/httponly keyword arguments.',
      remediationPattern: 'Explicitly configure secure=True, httponly=True, samesite="lax".',
      safeExample: 'response.set_cookie(key="session", value=sid, httponly=True, secure=True, samesite="lax")',
      vulnerableExample: 'response.set_cookie(key="session", value=sid)',
    },
    {
      cwe: 'CWE-1395',
      name: 'Vulnerable Dependency Reference',
      category: 'Supply Chain',
      severity: 'High',
      description:
        'Package dependencies pinned to versions with known published CVE advisories.',
      detectionMethod: 'Requirements parser comparing pinned versions against safety database.',
      remediationPattern: 'Bump dependency version to patched release.',
      safeExample: 'requests>=2.31.0',
      vulnerableExample: 'requests==2.18.4',
    },
    {
      cwe: 'CWE-20',
      name: 'Improper Input Validation',
      category: 'Input Validation',
      severity: 'Medium',
      description:
        'Unbounded payload size or unvalidated types accepted in request bodies.',
      detectionMethod: 'AST detection of raw request.body() consumption without size limits or Pydantic validation models.',
      remediationPattern: 'Enforce strongly-typed Pydantic schemas with length bounds.',
      safeExample: 'class InputModel(BaseModel):\n    item_id: int\n    quantity: conint(gt=0, le=100)',
      vulnerableExample: 'data = await request.json()',
    },
  ],

  benchmarkMetrics: {
    totalConfigured: 20,
    vulnerableTargets: 14,
    cleanBaselines: 6,
    detectionRecallPercent: 100.0,
    verifiedRemediationPercent: 100.0,
    cleanBaselineAccuracyPercent: 100.0,
    falsePositiveCount: 0,
    precisionPercent: 100.0,
    evaluationDatasetSummary:
      'Evaluated across 20 standardized benchmark targets: 14 deliberately vulnerable microservices representing OWASP Top 10 categories, and 6 clean negative controls verifying zero false-positive generation.',
  },

  limitations: [
    'White-Box AST Scope: ZeroDay inspects source code ASTs directly; it does not perform black-box network port scanning or dynamic crawler fuzzing.',
    'Language Support: Currently specialized for Python microservices (FastAPI, Flask, Starlette, ASGI/WSGI applications). Multi-language support (Go, TypeScript) is on the roadmap.',
    'Independent Verification Oracle: A patch is only marked VERIFIED_SECURE if syntax compiles, AST invariants pass, the exploit fails on replay, and the regression test suite passes.',
    'No Absolute Infallibility: ZeroDay is designed to augment security teams, not replace defense-in-depth or formal verification.',
  ],

  faqItems: [
    {
      question: 'What is ZeroDay?',
      answer:
        'ZeroDay is an autonomous vulnerability detection and verified remediation platform for software codebases. It combines static AST analysis to discover security sinks, isolated sandbox execution to reproduce exploits, NVIDIA Nemotron models hosted on Nebius Token Factory to synthesize minimal patches, and an independent 4-gate verification oracle to confirm that the patch fixes the flaw without causing regressions.',
    },
    {
      question: 'What problem does ZeroDay solve?',
      answer:
        'Traditional static analysis tools generate noisy reports with high false-positive rates, while generic LLM code assistants hallucinate syntax-valid patches that introduce new vulnerabilities or break business logic. ZeroDay bridges this gap by pairing autonomous Red Team exploit reproduction with Blue Team patch synthesis, verifying every proposed change through real test execution before presenting it to developers.',
    },
    {
      question: 'Which model and inference provider does ZeroDay use?',
      answer:
        'ZeroDay uses nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B (and supports nvidia/nemotron-3-super-120b-a12b for benchmark evaluation) hosted on Nebius Token Factory. Nebius Token Factory provides high-performance, cost-efficient inference via an OpenAI-compatible API protocol.',
    },
    {
      question: 'How does ZeroDay use threat intelligence grounding?',
      answer:
        'When a vulnerability sink is detected, ZeroDay queries the Tavily AI Search API to retrieve live, authoritative security documentation, MITRE CWE definitions, and OWASP cheat sheet guidance. This grounded context is fed to the Blue Team agent to ensure the synthesized patch adheres to standard security practices.',
    },
    {
      question: 'How are proposed fixes validated?',
      answer:
        'ZeroDay uses a Deterministic 4-Gate Invariant Oracle: Gate 1 verifies Python AST syntax compilation; Gate 2 checks static scan deltas to ensure the sink was removed without adding new sinks; Gate 3 replays the synthetic exploit probe against an isolated subprocess to verify it is blocked; and Gate 4 runs the repository regression test suite to ensure zero breaking changes.',
    },
    {
      question: 'How does ZeroDay handle false positives?',
      answer:
        'ZeroDay tests against both positive vulnerability controls and negative clean baseline controls. In our 20-case benchmark suite, ZeroDay achieved a 0% false positive rate across 6 clean baseline targets, correctly reporting zero findings and avoiding unnecessary code modifications.',
    },
    {
      question: 'Which vulnerability categories are supported?',
      answer:
        'ZeroDay currently supports 14 vulnerability categories including SQL Injection (CWE-89), OS Command Injection (CWE-78), Path Traversal (CWE-22), Broken Access Control / IDOR (CWE-284/CWE-639), Insecure Deserialization (CWE-502), SSRF (CWE-918), Hardcoded Credentials (CWE-798), Weak Cryptography (CWE-328), Open Redirect (CWE-601), Permissive CORS (CWE-942), Debug Endpoints (CWE-489), Insecure Cookies (CWE-614), Vulnerable Dependencies (CWE-1395), and Improper Input Validation (CWE-20).',
    },
    {
      question: 'Can developers run ZeroDay locally?',
      answer:
        'Yes. ZeroDay runs locally using Python 3.12+ (FastAPI) and Vite (React 19). Simply clone the repository, install dependencies via pip install -r requirements.txt and npm install in the frontend directory, set your NEBIUS_API_KEY and TAVILY_API_KEY in .env, and launch python main.py.',
    },
    {
      question: 'What is ZeroDay’s connection to the Nebius × NVIDIA Global AI Hackathon 2026?',
      answer:
        'ZeroDay was built and submitted for the Nebius × NVIDIA Global AI Hackathon 2026 under the Coding & Agentic Engineering track. It showcases how NVIDIA open-source models (Nemotron) combined with Nebius Token Factory inference can power end-to-end autonomous cyber defense agents.',
    },
    {
      question: 'How can developers inspect the code or contribute?',
      answer:
        'ZeroDay is an open-source project published under the MIT license. You can inspect the source code, run the benchmark suite, or contribute pull requests at https://github.com/darshansahare/ZeroDay.',
    },
  ],
};
