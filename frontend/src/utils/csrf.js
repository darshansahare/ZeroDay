/**
 * Utility helper to extract the double-submit CSRF token set by the backend in the `zd_csrf` cookie.
 */
export function getCsrfToken() {
  if (typeof document === 'undefined') return '';
  const match = document.cookie.match(/(?:^|;\s*)zd_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : '';
}

/**
 * Convenience helper to merge headers with X-CSRF-Token if present.
 */
export function authHeaders(extraHeaders = {}) {
  const token = getCsrfToken();
  const headers = { ...extraHeaders };
  if (token) {
    headers['X-CSRF-Token'] = token;
  }
  return headers;
}
