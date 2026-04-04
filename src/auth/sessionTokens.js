/**
 * Session Token Manager for NexusTrade.
 * Implements single-use session tokens for admin operations.
 * Each token can only be used ONCE - subsequent requests require a new token.
 *
 * Flow:
 *   1. Admin authenticates with enterprise credential → receives sessionId + oneTimeToken
 *   2. Admin uses oneTimeToken for ONE write operation
 *   3. Token is immediately invalidated after use
 *   4. Admin must request a new token for each subsequent write operation
 *
 * This prevents replay attacks and ensures each admin action is explicitly authorized.
 */

const crypto = require("crypto");

// In-memory session store. Resets on cold start.
// For production, replace with a persistent store (e.g., Netlify KV, Redis).
const activeSessions = new Map();

const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes
const TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes for one-time tokens

/**
 * Generates a cryptographically secure random token.
 * @param {number} [bytes=32] - Number of random bytes.
 * @returns {string} A hex-encoded random token.
 */
function generateSecureToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

/**
 * Creates a new admin session after enterprise credential validation.
 * @param {string} enterpriseId - The validated enterprise identifier.
 * @returns {{ sessionId: string, expiresAt: string }} The new session.
 */
function createSession(enterpriseId) {
  const sessionId = generateSecureToken(24);
  const now = Date.now();

  activeSessions.set(sessionId, {
    enterpriseId,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
    oneTimeToken: null,
    tokenExpiresAt: null,
    tokenUsed: true, // No token issued yet
  });

  return {
    sessionId,
    expiresAt: new Date(now + SESSION_TTL_MS).toISOString(),
  };
}

/**
 * Issues a new one-time token for a session. Invalidates any existing unused token.
 * @param {string} sessionId - The session to issue a token for.
 * @returns {{ token: string, expiresAt: string } | null} The one-time token, or null if session invalid.
 */
function issueOneTimeToken(sessionId) {
  const session = activeSessions.get(sessionId);
  if (!session) return null;

  const now = Date.now();
  if (now > session.expiresAt) {
    activeSessions.delete(sessionId);
    return null;
  }

  const token = generateSecureToken(32);
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const expiresAt = now + TOKEN_TTL_MS;

  session.oneTimeToken = tokenHash; // Store hashed version
  session.tokenExpiresAt = expiresAt;
  session.tokenUsed = false;

  return {
    token, // Return plaintext once - never stored in plaintext
    expiresAt: new Date(expiresAt).toISOString(),
  };
}

/**
 * Validates and consumes a one-time token. After calling this, the token is invalid.
 * @param {string} sessionId - The session ID.
 * @param {string} token - The one-time token to validate.
 * @returns {{ valid: boolean, reason?: string, enterpriseId?: string }} Validation result.
 */
function validateAndConsumeToken(sessionId, token) {
  const session = activeSessions.get(sessionId);

  if (!session) {
    return { valid: false, reason: "Session not found or expired" };
  }

  const now = Date.now();
  if (now > session.expiresAt) {
    activeSessions.delete(sessionId);
    return { valid: false, reason: "Session expired" };
  }

  if (!session.oneTimeToken || session.tokenUsed) {
    return { valid: false, reason: "No valid token for this session. Request a new token." };
  }

  if (now > session.tokenExpiresAt) {
    session.tokenUsed = true;
    return { valid: false, reason: "One-time token expired. Request a new token." };
  }

  if (typeof token !== "string" || token.length === 0) {
    return { valid: false, reason: "Token required" };
  }

  // Hash the provided token and compare to stored hash
  const providedHash = crypto.createHash("sha256").update(token).digest("hex");
  let tokensMatch = false;
  try {
    const storedBuf = Buffer.from(session.oneTimeToken, "hex");
    const providedBuf = Buffer.from(providedHash, "hex");
    tokensMatch =
      storedBuf.length === providedBuf.length &&
      crypto.timingSafeEqual(storedBuf, providedBuf);
  } catch {
    tokensMatch = false;
  }

  if (!tokensMatch) {
    return { valid: false, reason: "Invalid token" };
  }

  // Consume the token immediately - cannot be used again
  session.tokenUsed = true;
  session.oneTimeToken = null;

  return { valid: true, enterpriseId: session.enterpriseId };
}

/**
 * Validates an admin session (does NOT consume a token - for read operations).
 * @param {string} sessionId - The session ID to validate.
 * @returns {{ valid: boolean, reason?: string, enterpriseId?: string }} Validation result.
 */
function validateSession(sessionId) {
  const session = activeSessions.get(sessionId);

  if (!session) {
    return { valid: false, reason: "Session not found" };
  }

  const now = Date.now();
  if (now > session.expiresAt) {
    activeSessions.delete(sessionId);
    return { valid: false, reason: "Session expired" };
  }

  return { valid: true, enterpriseId: session.enterpriseId };
}

/**
 * Removes a session (logout).
 * @param {string} sessionId - The session to remove.
 */
function destroySession(sessionId) {
  activeSessions.delete(sessionId);
}

/**
 * Cleans up expired sessions (call periodically to prevent memory leaks).
 */
function cleanExpiredSessions() {
  const now = Date.now();
  for (const [id, session] of activeSessions.entries()) {
    if (now > session.expiresAt) {
      activeSessions.delete(id);
    }
  }
}

module.exports = {
  createSession,
  issueOneTimeToken,
  validateAndConsumeToken,
  validateSession,
  destroySession,
  cleanExpiredSessions,
  generateSecureToken,
};
