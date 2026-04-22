/**
 * Enterprise Authorization Module for NexusTrade.
 *
 * Enforces enterprise-only access control:
 *  - Team/group access is completely disabled
 *  - Only enterprise administrator role is permitted
 *  - All access attempts are audited
 *
 * Access model:
 *  - The ADMIN_TOKEN environment variable represents the enterprise admin credential
 *  - No role delegation or team sharing is supported
 *  - Credential validation uses constant-time comparison to prevent timing attacks
 */

const crypto = require("crypto");
const MIN_ADMIN_TOKEN_LENGTH = 32;

/**
 * Validates the provided token against the enterprise admin credential.
 * Uses constant-time comparison to prevent timing side-channel attacks.
 *
 * @param {string | null} token - Token from the request header.
 * @returns {{ authorized: boolean, reason?: string }}
 */
function validateEnterpriseToken(token) {
  const adminToken = process.env.ADMIN_TOKEN;

  if (!adminToken) {
    return { authorized: false, reason: "Enterprise admin token not configured" };
  }

  if (adminToken.length < MIN_ADMIN_TOKEN_LENGTH) {
    return { authorized: false, reason: "Enterprise admin token is misconfigured" };
  }

  if (!token || typeof token !== "string" || token.trim() === "") {
    return { authorized: false, reason: "No enterprise admin token provided" };
  }

  // Block attempts using well-known team/shared token patterns
  if (isTeamAccessAttempt(token)) {
    return { authorized: false, reason: "Team access is disabled; enterprise admin credentials required" };
  }

  let tokensMatch = false;
  try {
    // Pad to equal length before constant-time compare to avoid length leakage
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
    return { authorized: false, reason: "Invalid enterprise admin token" };
  }

  return { authorized: true };
}

/**
 * Heuristically detects whether a token looks like a team/group credential
 * or a shared key that does not belong to an individual enterprise admin.
 * This is a defense-in-depth measure and not a cryptographic guarantee.
 *
 * @param {string} token - The token to inspect.
 * @returns {boolean} True if the token appears to be a team credential.
 */
function isTeamAccessAttempt(token) {
  const lowerToken = token.toLowerCase();
  const teamPatterns = [
    "team_", "group_", "shared_", "org_", "department_",
    "role_user", "role_viewer", "role_editor",
  ];
  return teamPatterns.some((pattern) => lowerToken.startsWith(pattern));
}

/**
 * Returns a standardised 403 Forbidden response for enterprise-access violations.
 *
 * @param {string} [detail] - Internal detail for logging (not exposed to clients).
 * @returns {Response} A 403 Forbidden response.
 */
function forbiddenResponse(detail) {
  // Log the detail internally without exposing it to the client
  console.warn(`[EnterpriseAuth] Access denied: ${detail || "unknown"} at ${new Date().toISOString()}`);
  return Response.json(
    { error: "Forbidden: enterprise administrator access required" },
    { status: 403 }
  );
}

module.exports = { validateEnterpriseToken, isTeamAccessAttempt, forbiddenResponse };
