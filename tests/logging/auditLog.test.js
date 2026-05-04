"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const { auditLog, securityEvent, LOG_LEVEL, ACTION, hashForLog } = require("../../src/logging/auditLog.js");

// ---------------------------------------------------------------------------
// hashForLog
// ---------------------------------------------------------------------------
describe("hashForLog", () => {
  it("returns 'null' for null input", () => {
    assert.equal(hashForLog(null), "null");
  });

  it("returns 'null' for undefined input", () => {
    assert.equal(hashForLog(undefined), "null");
  });

  it("returns 'null' for non-string input", () => {
    assert.equal(hashForLog(42), "null");
  });

  it("includes the first 4 characters of the token", () => {
    const result = hashForLog("abcdefgh");
    assert.ok(result.startsWith("abcd"), "Should start with first 4 chars");
  });

  it("includes *** to indicate redaction", () => {
    const result = hashForLog("abcdefgh");
    assert.ok(result.includes("***"), "Should include *** redaction marker");
  });

  it("includes the length of the token in square brackets", () => {
    const result = hashForLog("abcdefgh");
    assert.ok(result.includes("[8]"), "Should include token length");
  });

  it("works for short tokens (length < 4)", () => {
    const result = hashForLog("ab");
    assert.ok(result.includes("***"), "Should still include redaction marker");
    assert.ok(result.includes("[2]"), "Should include token length");
  });
});

// ---------------------------------------------------------------------------
// LOG_LEVEL and ACTION constants
// ---------------------------------------------------------------------------
describe("LOG_LEVEL constants", () => {
  it("defines INFO", () => {
    assert.equal(LOG_LEVEL.INFO, "INFO");
  });

  it("defines WARN", () => {
    assert.equal(LOG_LEVEL.WARN, "WARN");
  });

  it("defines ERROR", () => {
    assert.equal(LOG_LEVEL.ERROR, "ERROR");
  });

  it("defines SECURITY", () => {
    assert.equal(LOG_LEVEL.SECURITY, "SECURITY");
  });
});

describe("ACTION constants", () => {
  it("defines ADMIN_LOGIN", () => {
    assert.equal(ACTION.ADMIN_LOGIN, "ADMIN_LOGIN");
  });

  it("defines BALANCE_UPDATED", () => {
    assert.equal(ACTION.BALANCE_UPDATED, "BALANCE_UPDATED");
  });

  it("defines UNAUTHORIZED_ACCESS", () => {
    assert.equal(ACTION.UNAUTHORIZED_ACCESS, "UNAUTHORIZED_ACCESS");
  });

  it("defines INJECTION_BLOCKED", () => {
    assert.equal(ACTION.INJECTION_BLOCKED, "INJECTION_BLOCKED");
  });
});

// ---------------------------------------------------------------------------
// auditLog
// ---------------------------------------------------------------------------
describe("auditLog", () => {
  let logs;
  let warnings;
  let errors;
  const originalLog = console.log;
  const originalWarn = console.warn;
  const originalError = console.error;

  beforeEach(() => {
    logs = [];
    warnings = [];
    errors = [];
    console.log = (...args) => logs.push(args.join(" "));
    console.warn = (...args) => warnings.push(args.join(" "));
    console.error = (...args) => errors.push(args.join(" "));
  });

  afterEach(() => {
    console.log = originalLog;
    console.warn = originalWarn;
    console.error = originalError;
  });

  it("writes a log entry with the [AUDIT] prefix", () => {
    auditLog({ action: ACTION.ADMIN_LOGIN, level: LOG_LEVEL.INFO });
    assert.ok(logs.some((l) => l.includes("[AUDIT]")));
  });

  it("returns the log entry object", () => {
    const entry = auditLog({ action: ACTION.ADMIN_LOGIN });
    assert.equal(entry.action, ACTION.ADMIN_LOGIN);
  });

  it("entry includes a timestamp", () => {
    const entry = auditLog({ action: ACTION.ADMIN_LOGIN });
    assert.ok(entry.timestamp, "Should have a timestamp");
    assert.ok(!isNaN(new Date(entry.timestamp).getTime()), "Timestamp should be valid");
  });

  it("entry includes the action field", () => {
    const entry = auditLog({ action: ACTION.WITHDRAWAL_REQUESTED });
    assert.equal(entry.action, ACTION.WITHDRAWAL_REQUESTED);
  });

  it("entry includes optional fields when provided", () => {
    const entry = auditLog({
      action: ACTION.BALANCE_UPDATED,
      userId: "user-123",
      ip: "1.2.3.4",
      reason: "Admin adjustment",
    });
    assert.equal(entry.userId, "user-123");
    assert.equal(entry.ip, "1.2.3.4");
    assert.equal(entry.reason, "Admin adjustment");
  });

  it("omits optional fields when they are not provided", () => {
    const entry = auditLog({ action: ACTION.ADMIN_LOGIN });
    assert.equal(entry.userId, undefined);
    assert.equal(entry.ip, undefined);
  });

  it("uses console.error for ERROR level", () => {
    auditLog({ action: ACTION.TRADE_FAILED, level: LOG_LEVEL.ERROR });
    assert.ok(errors.some((e) => e.includes("[AUDIT]")));
    assert.equal(logs.filter((l) => l.includes("[AUDIT]")).length, 0);
  });

  it("uses console.error for SECURITY level", () => {
    auditLog({ action: ACTION.UNAUTHORIZED_ACCESS, level: LOG_LEVEL.SECURITY });
    assert.ok(errors.some((e) => e.includes("[AUDIT]")));
  });

  it("uses console.warn for WARN level", () => {
    auditLog({ action: ACTION.ADMIN_LOGIN_FAILED, level: LOG_LEVEL.WARN });
    assert.ok(warnings.some((w) => w.includes("[AUDIT]")));
  });

  it("uses console.log for INFO level", () => {
    auditLog({ action: ACTION.ADMIN_LOGIN, level: LOG_LEVEL.INFO });
    assert.ok(logs.some((l) => l.includes("[AUDIT]")));
  });

  it("defaults actor to 'system'", () => {
    const entry = auditLog({ action: ACTION.ADMIN_LOGIN });
    assert.equal(entry.actor, "system");
  });

  it("defaults status to 'success'", () => {
    const entry = auditLog({ action: ACTION.ADMIN_LOGIN });
    assert.equal(entry.status, "success");
  });

  it("includes changes when provided", () => {
    const entry = auditLog({
      action: ACTION.BALANCE_UPDATED,
      changes: { before: 100, after: 200 },
    });
    assert.deepEqual(entry.changes, { before: 100, after: 200 });
  });
});

// ---------------------------------------------------------------------------
// securityEvent
// ---------------------------------------------------------------------------
describe("securityEvent", () => {
  let errors;
  const originalError = console.error;

  beforeEach(() => {
    errors = [];
    console.error = (...args) => errors.push(args.join(" "));
  });

  afterEach(() => {
    console.error = originalError;
  });

  it("returns a log entry with SECURITY level", () => {
    const entry = securityEvent(ACTION.INJECTION_BLOCKED, { ip: "1.2.3.4" });
    assert.equal(entry.level, LOG_LEVEL.SECURITY);
  });

  it("returns a log entry with the provided action", () => {
    const entry = securityEvent(ACTION.UNAUTHORIZED_ACCESS, {});
    assert.equal(entry.action, ACTION.UNAUTHORIZED_ACCESS);
  });

  it("logs to console.error (security events use error stream)", () => {
    securityEvent(ACTION.INJECTION_BLOCKED, { reason: "blocked" });
    assert.ok(errors.some((e) => e.includes("[AUDIT]")));
  });

  it("merges additional details into the log entry", () => {
    const entry = securityEvent(ACTION.RATE_LIMIT_EXCEEDED, {
      ip: "9.9.9.9",
      userId: "user-42",
    });
    assert.equal(entry.ip, "9.9.9.9");
    assert.equal(entry.userId, "user-42");
  });
});
