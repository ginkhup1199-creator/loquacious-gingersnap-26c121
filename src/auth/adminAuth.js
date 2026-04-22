/**
 * Admin Authorization Module for NexusTrade.
 * Validates admin tokens and protects wallet modification operations.
 */

const crypto = require("crypto");
const MIN_ADMIN_TOKEN_LENGTH = 32;

/**
 * Validates that the provided token matches the configured ADMIN_TOKEN.
 * Does not log the token value to avoid leaking secrets.
 *
 * @param {string | null} token - The token from the request header.
 * @returns {{ authorized: boolean, reason?: string }} Authorization result.
 */
function validateAdminToken(token) {
  const adminToken = process.env.ADMIN_TOKEN;

  if (!adminToken) {
    return { authorized: false, reason: "Admin token not configured" };
  }

  if (!token || typeof token !== "string") {
    return { authorized: false, reason: "No admin token provided" };
  }

  if (adminToken.length < MIN_ADMIN_TOKEN_LENGTH) {
    return { authorized: false, reason: "Admin token is misconfigured" };
  }

  // Constant-time compare to reduce timing side-channel leakage.
  let tokensMatch = false;
  try {
    const maxLen = Math.max(token.length, adminToken.length);
    const tokenBuf = Buffer.alloc(maxLen);
    const adminBuf = Buffer.alloc(maxLen);
    Buffer.from(token).copy(tokenBuf);
    Buffer.from(adminToken).copy(adminBuf);
    tokensMatch =
      token.length === adminToken.length &&
      crypto.timingSafeEqual(tokenBuf, adminBuf);
  } catch {
    tokensMatch = false;
  }

  if (!tokensMatch) {
    return { authorized: false, reason: "Invalid admin token" };
  }

  return { authorized: true };
}

/**
 * Logs an admin operation without exposing sensitive values.
 *
 * @param {string} operation - A description of the operation performed.
 * @param {boolean} success - Whether the operation succeeded.
 */
function logAdminOperation(operation, success) {
  const status = success ? "SUCCESS" : "DENIED";
  console.log(`[AdminAuth] ${status}: ${operation} at ${new Date().toISOString()}`);
}

/**
 * Returns an unauthorized Response with a sanitized error message.
 * Never exposes token values or internal configuration details.
 *
 * @param {string} reason - The reason for denying access (safe to log, not exposed to client).
 * @returns {Response} A 401 Unauthorized response.
 */
function unauthorizedResponse(reason) {
  logAdminOperation(reason, false);
  return Response.json({ error: "Unauthorized" }, { status: 401 });
}

module.exports = { validateAdminToken, logAdminOperation, unauthorizedResponse };
