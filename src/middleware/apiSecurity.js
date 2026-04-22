/**
 * API Security Middleware for NexusTrade.
 * Provides token validation, rate limiting, and request validation
 * for admin-protected endpoints in Netlify Functions.
 */

const crypto = require("crypto");

// Simple in-memory rate limiter (resets on function cold start).
// NOTE: Each Netlify Function instance maintains its own Map, so limits
// are per-instance rather than global. For global rate limiting use a
// shared store such as Redis or a Netlify KV store.
const requestCounts = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 30;
const MIN_ADMIN_TOKEN_LENGTH = 32;

/**
 * Checks if the request IP has exceeded the rate limit.
 * @param {string} ip - The client IP address.
 * @returns {boolean} True if rate limit exceeded.
 */
function isRateLimited(ip) {
  const now = Date.now();

  // Remove expired entries to prevent unbounded memory growth
  for (const [key, entry] of requestCounts.entries()) {
    if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
      requestCounts.delete(key);
    }
  }

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

  if (adminToken.length < MIN_ADMIN_TOKEN_LENGTH) {
    return {
      valid: false,
      response: Response.json(
        { error: "Admin token is misconfigured" },
        { status: 503 }
      ),
    };
  }

  const token = req.headers.get("X-Admin-Token");
  if (!token) {
    return {
      valid: false,
      response: Response.json({ error: "Unauthorized" }, { status: 401 }),
    };
  }

  // Use constant-time comparison to prevent timing attacks
  let tokensMatch = false;
  try {
    const tokenBuf = Buffer.from(token);
    const adminBuf = Buffer.from(adminToken);
    tokensMatch =
      tokenBuf.length === adminBuf.length &&
      crypto.timingSafeEqual(tokenBuf, adminBuf);
  } catch {
    tokensMatch = false;
  }

  if (!tokensMatch) {
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
