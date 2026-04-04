/**
 * Enterprise Security Audit Logger for NexusTrade.
 *
 * Provides structured audit logging for:
 *  - Authentication attempts (success / failure)
 *  - Session creation, use, and destruction
 *  - Admin write operations
 *  - Suspicious / blocked requests
 *
 * Design principles:
 *  - NEVER log token values, passwords, or secrets
 *  - NEVER log full wallet addresses (truncate to first 8 + last 4 chars)
 *  - Log just enough detail to support incident investigation
 *  - All events include ISO 8601 timestamp and event category
 */

/** @enum {string} */
const AuditEvent = {
  AUTH_SUCCESS: "AUTH_SUCCESS",
  AUTH_FAILURE: "AUTH_FAILURE",
  SESSION_CREATED: "SESSION_CREATED",
  SESSION_USED: "SESSION_USED",
  SESSION_EXPIRED: "SESSION_EXPIRED",
  SESSION_DESTROYED: "SESSION_DESTROYED",
  ADMIN_WRITE: "ADMIN_WRITE",
  ADMIN_READ: "ADMIN_READ",
  INJECTION_BLOCKED: "INJECTION_BLOCKED",
  RATE_LIMITED: "RATE_LIMITED",
  INVALID_INPUT: "INVALID_INPUT",
  ACCESS_DENIED: "ACCESS_DENIED",
};

/**
 * Truncates a wallet address to a safe display form.
 * e.g. "0xdAC17F958D2ee523a2206206994597C13D831ec7" → "0xdAC17F9…31ec7"
 *
 * @param {string | undefined} address
 * @returns {string}
 */
function maskWallet(address) {
  if (!address || typeof address !== "string") return "(none)";
  if (address.length <= 12) return address;
  return `${address.slice(0, 8)}…${address.slice(-4)}`;
}

/**
 * Masks a session ID to avoid leaking the full secret in logs.
 *
 * @param {string | undefined} sessionId
 * @returns {string}
 */
function maskSessionId(sessionId) {
  if (!sessionId || typeof sessionId !== "string") return "(none)";
  return `${sessionId.slice(0, 8)}…`;
}

/**
 * Emits a structured audit log entry to stdout.
 * In production these logs are captured by the Netlify log pipeline.
 *
 * @param {string} event - One of the AuditEvent values.
 * @param {object} [details] - Additional context (must not contain secrets).
 */
function auditLog(event, details = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    event,
    ...details,
  };

  // Scrub any accidentally-included sensitive fields before logging
  delete entry.token;
  delete entry.adminToken;
  delete entry.password;
  delete entry.secret;

  console.log(`[AUDIT] ${JSON.stringify(entry)}`);
}

/**
 * Logs a successful or failed authentication attempt.
 *
 * @param {boolean} success
 * @param {string} [reason] - Failure reason (safe to log).
 * @param {string} [ip]
 */
function logAuth(success, reason, ip) {
  auditLog(success ? AuditEvent.AUTH_SUCCESS : AuditEvent.AUTH_FAILURE, {
    reason: success ? undefined : reason,
    ip: ip || "(unknown)",
  });
}

/**
 * Logs a session lifecycle event.
 *
 * @param {string} event - SESSION_CREATED | SESSION_USED | SESSION_EXPIRED | SESSION_DESTROYED
 * @param {string} [sessionId] - Will be masked before logging.
 * @param {string} [ip]
 */
function logSession(event, sessionId, ip) {
  auditLog(event, {
    sessionId: maskSessionId(sessionId),
    ip: ip || "(unknown)",
  });
}

/**
 * Logs an admin write operation.
 *
 * @param {string} operation - Human-readable description (e.g. "update-balance").
 * @param {boolean} success
 * @param {string} [walletAddress] - Will be masked.
 * @param {string} [ip]
 */
function logAdminWrite(operation, success, walletAddress, ip) {
  auditLog(success ? AuditEvent.ADMIN_WRITE : AuditEvent.ACCESS_DENIED, {
    operation,
    wallet: maskWallet(walletAddress),
    ip: ip || "(unknown)",
  });
}

/**
 * Logs a blocked injection attempt.
 *
 * @param {string} reason - Safe description of the blocked pattern.
 * @param {string} [ip]
 */
function logInjectionBlocked(reason, ip) {
  auditLog(AuditEvent.INJECTION_BLOCKED, {
    reason,
    ip: ip || "(unknown)",
  });
}

module.exports = {
  AuditEvent,
  auditLog,
  logAuth,
  logSession,
  logAdminWrite,
  logInjectionBlocked,
  maskWallet,
  maskSessionId,
};
