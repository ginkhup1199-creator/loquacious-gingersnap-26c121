/**
 * Security Headers configuration for NexusTrade.
 *
 * Returns a standard set of security headers to attach to every HTTP response.
 *
 * Headers applied:
 *  - Content-Security-Policy  – restrict resource origins to prevent XSS
 *  - X-Content-Type-Options   – prevent MIME-sniffing
 *  - X-Frame-Options          – prevent clickjacking
 *  - X-XSS-Protection         – legacy browser XSS filter (defence-in-depth)
 *  - Referrer-Policy          – limit referrer leakage
 *  - Permissions-Policy       – disable sensitive browser APIs
 *  - Strict-Transport-Security – enforce HTTPS (HSTS)
 *  - Cache-Control            – prevent caching of sensitive API responses
 */

/**
 * Returns the standard security response headers as a plain object.
 *
 * @param {{ cache?: boolean }} [options]
 *   - cache: if true, allow caching (for public, non-sensitive responses).
 *            Defaults to false (no-store).
 * @returns {Record<string, string>}
 */
function getSecurityHeaders(options = {}) {
  const headers = {
    // Prevent MIME-type confusion attacks
    "X-Content-Type-Options": "nosniff",

    // Prevent clickjacking via iframes
    "X-Frame-Options": "DENY",

    // Legacy XSS protection for older browsers
    "X-XSS-Protection": "1; mode=block",

    // Limit information leakage in the Referer header
    "Referrer-Policy": "strict-origin-when-cross-origin",

    // Disable browser APIs that could be abused
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",

    // Enforce HTTPS for 1 year (only meaningful in production over TLS)
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",

    // Restrict resource origins – adjust 'self' sources as your CSP evolves
    "Content-Security-Policy": [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'", // unsafe-inline needed for inline scripts in admin.html
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
  };

  if (!options.cache) {
    headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private";
    headers["Pragma"] = "no-cache";
  }

  return headers;
}

/**
 * Applies security headers to an existing Headers instance (mutates in place).
 *
 * @param {Headers} headers - A Fetch API Headers object to augment.
 * @param {{ cache?: boolean }} [options]
 */
function applySecurityHeaders(headers, options = {}) {
  const secHeaders = getSecurityHeaders(options);
  for (const [key, value] of Object.entries(secHeaders)) {
    headers.set(key, value);
  }
}

/**
 * Wraps a JSON payload in a Response with security headers attached.
 *
 * @param {unknown} body - The value to serialise as JSON.
 * @param {{ status?: number, cache?: boolean }} [options]
 * @returns {Response}
 */
function secureJsonResponse(body, options = {}) {
  const status = options.status ?? 200;
  const secHeaders = getSecurityHeaders({ cache: options.cache });
  secHeaders["Content-Type"] = "application/json";

  return new Response(JSON.stringify(body), {
    status,
    headers: secHeaders,
  });
}

module.exports = { getSecurityHeaders, applySecurityHeaders, secureJsonResponse };
