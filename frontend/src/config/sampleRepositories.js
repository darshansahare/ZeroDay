/**
 * ZeroDay Arena - Intentionally Vulnerable Sample Repositories Configuration.
 */

export const SAMPLE_REPOSITORIES = [
  {
    id: 'sample-sql-injection',
    name: 'SQL Injection',
    repo: 'darshansahare/zeroday-test-1',
    url: 'https://github.com/darshansahare/zeroday-test-1',
    description: 'Unparameterized query execution in microservice endpoint vulnerable to data exfiltration.',
    language: 'Python',
    targetPath: 'app.py',
    cwe: 'CWE-89',
    isConfigured: true,
  },
  {
    id: 'sample-path-traversal',
    name: 'Path Traversal',
    repo: 'darshansahare/zeroday-test-2',
    url: 'https://github.com/darshansahare/zeroday-test-2',
    description: 'Arbitrary file read vulnerability via unsanitized file path parameters escaping document root.',
    language: 'Python',
    targetPath: 'app.py',
    cwe: 'CWE-22',
    isConfigured: true,
  },
  {
    id: 'sample-broken-access-control',
    name: 'Broken Access Control',
    repo: 'darshansahare/zeroday-test-3',
    url: 'https://github.com/darshansahare/zeroday-test-3',
    description: 'Broken access control vulnerability (CWE-284) allowing unauthorized access to tenant records.',
    language: 'Python',
    targetPath: 'app.py',
    cwe: 'CWE-284',
    isConfigured: true,
  },
];
