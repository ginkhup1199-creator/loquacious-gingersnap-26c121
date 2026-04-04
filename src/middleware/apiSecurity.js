/**
 * API Security Middleware for NexusTrade.
 * Provides token validation, rate limiting, and request validation
 * for admin-protected endpoints in Netlify Functions.
 */

// Simple in-memory rate limiter (resets on function cold start)
const requestCounts = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 30;

/**
 * Checks if the request IP has exceeded the rate limit.
 * @param {string} ip - The client IP address.
 * @returns {boolean} True if rate limit exceeded.
 */
function isRateLimited(ip) {
  const now = Date.now();
  const entry = requestCounts.get(ip);

  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    requestCounts.set(ip, { count: 1, windowStart: now });
    return false;
  }

  entry.count += 1;
  if (entry.count > RATE_LIMIT_MAX_REQUESTS) {
    return true;
  }

  return false;
}

/**
 * Validates the admin token from request headers.
 * @param {Request} req - The incoming request.
 * @returns {{ valid: boolean, response?: Response }} Validation result.
 */
function validateAdminToken(req) {
  const adminToken = process.env.ADMIN_TOKEN;

  if (!adminToken) {
    return {
      valid: false,
      response: Response.json(
        { error: "Admin token not configured" },
        { status: 503 }
      ),
    };
  }

  const token = req.headers.get("X-Admin-Token");
  if (!token || token !== adminToken) {
    return {
      valid: false,
      response: Response.json({ error: "Unauthorized" }, { status: 401 }),
    };
  }

  return { valid: true };
}

/**
 * Applies rate limiting for a given client IP.
 * @param {string} ip - The client IP address.
 * @returns {{ limited: boolean, response?: Response }} Rate limit result.
 */
function applyRateLimit(ip) {
  if (isRateLimited(ip)) {
    return {
      limited: true,
      response: Response.json(
        { error: "Too many requests. Please try again later." },
        { status: 429 }
      ),
    };
  }
  return { limited: false };
}

/**
 * Validates that request body is a non-null object.
 * @param {unknown} body - The parsed request body.
 * @returns {boolean} True if the body is valid.
 */
function validateRequestBody(body) {
  return body !== null && typeof body === "object" && !Array.isArray(body);
}

module.exports = { validateAdminToken, applyRateLimit, validateRequestBody };
