/**
 * Audit Logging Module for NexusTrade.
 * Records all significant operations for security compliance and incident investigation.
 * Logs are written to console (captured by Netlify Function logs) and can be
 * extended to write to a persistent store.
 */

/**
 * Log levels for filtering and severity classification.
 */
const LOG_LEVEL = {
  INFO: "INFO",
  WARN: "WARN",
  ERROR: "ERROR",
  SECURITY: "SECURITY",
};

/**
 * Action categories for structured querying.
 */
const ACTION = {
  // Admin actions
  ADMIN_LOGIN: "ADMIN_LOGIN",
  ADMIN_LOGIN_FAILED: "ADMIN_LOGIN_FAILED",
  ADMIN_TOKEN_CREATED: "ADMIN_TOKEN_CREATED",
  ADMIN_TOKEN_USED: "ADMIN_TOKEN_USED",
  ADMIN_TOKEN_EXPIRED: "ADMIN_TOKEN_EXPIRED",
  ADMIN_TOKEN_INVALID: "ADMIN_TOKEN_INVALID",
  ADMIN_SESSION_CREATED: "ADMIN_SESSION_CREATED",
  ADMIN_SESSION_EXPIRED: "ADMIN_SESSION_EXPIRED",

  // Balance actions
  BALANCE_READ: "BALANCE_READ",
  BALANCE_UPDATED: "BALANCE_UPDATED",
  BALANCE_UPDATE_FAILED: "BALANCE_UPDATE_FAILED",

  // Trade actions
  TRADE_CREATED: "TRADE_CREATED",
  TRADE_COMPLETED: "TRADE_COMPLETED",
  TRADE_FAILED: "TRADE_FAILED",

  // Wallet actions
  WALLET_CREATED: "WALLET_CREATED",
  WALLET_ADDRESS_UPDATED: "WALLET_ADDRESS_UPDATED",

  // Transaction actions
  TRANSACTION_CREATED: "TRANSACTION_CREATED",
  TRANSACTION_PROCESSED: "TRANSACTION_PROCESSED",
  TRANSACTION_FAILED: "TRANSACTION_FAILED",

  // Withdrawal actions
  WITHDRAWAL_REQUESTED: "WITHDRAWAL_REQUESTED",
  WITHDRAWAL_PROCESSED: "WITHDRAWAL_PROCESSED",
  WITHDRAWAL_REJECTED: "WITHDRAWAL_REJECTED",

  // User actions
  USER_REGISTERED: "USER_REGISTERED",
  USER_KYC_SUBMITTED: "USER_KYC_SUBMITTED",
  USER_KYC_APPROVED: "USER_KYC_APPROVED",
  USER_KYC_REJECTED: "USER_KYC_REJECTED",

  // Security events
  RATE_LIMIT_EXCEEDED: "RATE_LIMIT_EXCEEDED",
  INJECTION_BLOCKED: "INJECTION_BLOCKED",
  UNAUTHORIZED_ACCESS: "UNAUTHORIZED_ACCESS",

  // Feature management
  FEATURES_UPDATED: "FEATURES_UPDATED",
  LEVELS_UPDATED: "LEVELS_UPDATED",
  SETTINGS_UPDATED: "SETTINGS_UPDATED",
};

/**
 * Creates a structured audit log entry and writes it to console.
 *
 * @param {object} params - Log parameters.
 * @param {string} params.action - The action being logged (use ACTION constants).
 * @param {string} params.level - Log level (use LOG_LEVEL constants).
 * @param {string} [params.actor] - "user", "admin", or "system".
 * @param {string} [params.userId] - The user ID involved, if any.
 * @param {string} [params.adminId] - The admin session ID, if any (hashed, not the raw token).
 * @param {string} [params.resource] - The resource being accessed/modified.
 * @param {object} [params.changes] - Description of changes made (no sensitive values).
 * @param {string} [params.status] - "success" or "failure".
 * @param {string} [params.ip] - The client IP address.
 * @param {string} [params.reason] - Reason for the action or failure.
 */
function auditLog({
  action,
  level = LOG_LEVEL.INFO,
  actor = "system",
  userId = null,
  adminId = null,
  resource = null,
  changes = null,
  status = "success",
  ip = null,
  reason = null,
}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    action,
    actor,
    status,
    ...(userId && { userId }),
    ...(adminId && { adminId }),
    ...(resource && { resource }),
    ...(changes && { changes }),
    ...(ip && { ip }),
    ...(reason && { reason }),
  };

  // Write to console - Netlify captures these in function logs
  const logFn =
    level === LOG_LEVEL.ERROR || level === LOG_LEVEL.SECURITY
      ? console.error
      : level === LOG_LEVEL.WARN
      ? console.warn
      : console.log;

  logFn(`[AUDIT] ${JSON.stringify(entry)}`);

  return entry;
}

/**
 * Logs a security event with elevated severity.
 */
function securityEvent(action, details) {
  return auditLog({
    ...details,
    action,
    level: LOG_LEVEL.SECURITY,
  });
}

/**
 * Hashes a token for safe logging (never log raw tokens).
 * @param {string} token - The token to hash for logging.
 * @returns {string} A safe representation for logs.
 */
function hashForLog(token) {
  if (!token || typeof token !== "string") return "null";
  // Show first 4 chars + hash indicator (enough to correlate without exposing)
  return token.slice(0, 4) + "***[" + token.length + "]";
}

module.exports = { auditLog, securityEvent, LOG_LEVEL, ACTION, hashForLog };
