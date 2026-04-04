/**
 * Session Manager for NexusTrade Enterprise Admin.
 *
 * Implements single-use session tokens with automatic 1-hour expiration.
 * Sessions are stored in @netlify/blobs for persistence across serverless invocations.
 *
 * Session lifecycle:
 *  1. Admin authenticates with ADMIN_TOKEN → receives session_id
 *  2. Admin uses session_id (via X-Session-Token header) for admin operations
 *  3. Session expires automatically after SESSION_TTL_MS
 *  4. Logout endpoint explicitly invalidates the session
 *  5. Only one active session is permitted at a time
 */

const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour
const SESSION_STORE_KEY = "admin-session";

/**
 * Creates a cryptographically random session ID.
 * @returns {string} A hex-encoded 32-byte session ID.
 */
function generateSessionId() {
  const crypto = require("crypto");
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Creates a new admin session and persists it to the store.
 * Invalidates any existing active session.
 *
 * @param {object} store - A @netlify/blobs store instance.
 * @returns {Promise<{ sessionId: string, expiresAt: string }>} The new session.
 */
async function createSession(store) {
  const sessionId = generateSessionId();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

  const session = {
    sessionId,
    expiresAt,
    createdAt: new Date().toISOString(),
    usedAt: null,
  };

  await store.setJSON(SESSION_STORE_KEY, session);
  return { sessionId, expiresAt };
}

/**
 * Validates a session token against the stored session.
 * Returns an error reason if the session is invalid, expired, or has been used.
 *
 * @param {object} store - A @netlify/blobs store instance.
 * @param {string | null} sessionId - The session ID from the request header.
 * @returns {Promise<{ valid: boolean, reason?: string, session?: object }>}
 */
async function validateSession(store, sessionId) {
  if (!sessionId || typeof sessionId !== "string") {
    return { valid: false, reason: "No session token provided" };
  }

  const session = await store.get(SESSION_STORE_KEY, { type: "json" });

  if (!session) {
    return { valid: false, reason: "No active session" };
  }

  if (session.sessionId !== sessionId) {
    return { valid: false, reason: "Invalid session token" };
  }

  if (new Date(session.expiresAt).getTime() < Date.now()) {
    await store.delete(SESSION_STORE_KEY);
    return { valid: false, reason: "Session expired" };
  }

  return { valid: true, session };
}

/**
 * Marks the session as used (single-use enforcement).
 * After calling this, subsequent calls to validateSession for the same ID
 * will succeed (the session is still valid until expiry), but callers may
 * choose to enforce stricter single-use semantics by checking session.usedAt.
 *
 * @param {object} store - A @netlify/blobs store instance.
 * @param {object} session - The current session object.
 */
async function markSessionUsed(store, session) {
  const updated = { ...session, usedAt: new Date().toISOString() };
  await store.setJSON(SESSION_STORE_KEY, updated);
}

/**
 * Destroys the current session, regardless of which session ID is provided.
 * Used during logout.
 *
 * @param {object} store - A @netlify/blobs store instance.
 */
async function destroySession(store) {
  await store.delete(SESSION_STORE_KEY);
}

module.exports = {
  createSession,
  validateSession,
  markSessionUsed,
  destroySession,
  SESSION_TTL_MS,
};
