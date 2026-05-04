"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const {
  AuditEvent,
  auditLog,
  logAuth,
  logSession,
  logAdminWrite,
  logInjectionBlocked,
  maskWallet,
  maskSessionId,
} = require("../../src/logging/securityAudit.js");

// ---------------------------------------------------------------------------
// maskWallet
// ---------------------------------------------------------------------------
describe("maskWallet", () => {
  it("returns '(none)' for undefined input", () => {
    assert.equal(maskWallet(undefined), "(none)");
  });

  it("returns '(none)' for null input", () => {
    assert.equal(maskWallet(null), "(none)");
  });

  it("returns '(none)' for non-string input", () => {
    assert.equal(maskWallet(42), "(none)");
  });

  it("returns the address unchanged when 12 chars or shorter", () => {
    assert.equal(maskWallet("0xABCDEF"), "0xABCDEF");
  });

  it("masks a long Ethereum address", () => {
    const addr = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    const result = maskWallet(addr);
    // Should start with first 8 chars and end with last 4 chars
    assert.ok(result.startsWith(addr.slice(0, 8)), "Should start with first 8 chars");
    assert.ok(result.endsWith(addr.slice(-4)), "Should end with last 4 chars");
    assert.ok(result.includes("…"), "Should include ellipsis");
    assert.ok(result.length < addr.length, "Masked address should be shorter than original");
  });

  it("does not expose the full wallet address in the masked result", () => {
    const addr = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    const result = maskWallet(addr);
    assert.notEqual(result, addr);
  });
});

// ---------------------------------------------------------------------------
// maskSessionId
// ---------------------------------------------------------------------------
describe("maskSessionId", () => {
  it("returns '(none)' for undefined input", () => {
    assert.equal(maskSessionId(undefined), "(none)");
  });

  it("returns '(none)' for null input", () => {
    assert.equal(maskSessionId(null), "(none)");
  });

  it("returns '(none)' for non-string input", () => {
    assert.equal(maskSessionId(42), "(none)");
  });

  it("includes only the first 8 chars of the session ID followed by ellipsis", () => {
    const sessionId = "abcdef1234567890abcdef1234567890";
    const result = maskSessionId(sessionId);
    assert.ok(result.startsWith("abcdef12"), "Should start with first 8 chars");
    assert.ok(result.includes("…"), "Should include ellipsis");
    assert.ok(result.length < sessionId.length, "Should be shorter than original");
  });

  it("does not expose the full session ID", () => {
    const sessionId = "abcdef1234567890abcdef1234567890";
    const result = maskSessionId(sessionId);
    assert.notEqual(result, sessionId);
  });
});

// ---------------------------------------------------------------------------
// auditLog (securityAudit)
// ---------------------------------------------------------------------------
describe("auditLog (securityAudit)", () => {
  let logs;
  const originalLog = console.log;

  beforeEach(() => {
    logs = [];
    console.log = (...args) => logs.push(args.join(" "));
  });

  afterEach(() => {
    console.log = originalLog;
  });

  it("writes an entry prefixed with [AUDIT]", () => {
    auditLog(AuditEvent.AUTH_SUCCESS);
    assert.ok(logs.some((l) => l.includes("[AUDIT]")));
  });

  it("entry includes the event type", () => {
    auditLog(AuditEvent.AUTH_SUCCESS);
    assert.ok(logs.some((l) => l.includes(AuditEvent.AUTH_SUCCESS)));
  });

  it("entry includes a timestamp", () => {
    auditLog(AuditEvent.AUTH_SUCCESS);
    assert.ok(logs.some((l) => /\d{4}-\d{2}-\d{2}T/.test(l)));
  });

  it("merges provided details into the log entry", () => {
    auditLog(AuditEvent.AUTH_FAILURE, { reason: "bad token", ip: "1.2.3.4" });
    const entry = JSON.parse(logs[0].replace("[AUDIT] ", ""));
    assert.equal(entry.reason, "bad token");
    assert.equal(entry.ip, "1.2.3.4");
  });

  it("scrubs sensitive fields (token) from the details", () => {
    auditLog(AuditEvent.AUTH_SUCCESS, { token: "super-secret-token" });
    const entry = JSON.parse(logs[0].replace("[AUDIT] ", ""));
    assert.equal(entry.token, undefined);
  });

  it("scrubs adminToken from the details", () => {
    auditLog(AuditEvent.ADMIN_WRITE, { adminToken: "secret-admin-key" });
    const entry = JSON.parse(logs[0].replace("[AUDIT] ", ""));
    assert.equal(entry.adminToken, undefined);
  });

  it("scrubs password from the details", () => {
    auditLog(AuditEvent.AUTH_SUCCESS, { password: "hunter2" });
    const entry = JSON.parse(logs[0].replace("[AUDIT] ", ""));
    assert.equal(entry.password, undefined);
  });

  it("scrubs secret from the details", () => {
    auditLog(AuditEvent.SESSION_CREATED, { secret: "my-secret" });
    const entry = JSON.parse(logs[0].replace("[AUDIT] ", ""));
    assert.equal(entry.secret, undefined);
  });
});

// ---------------------------------------------------------------------------
// AuditEvent constants
// ---------------------------------------------------------------------------
describe("AuditEvent constants", () => {
  it("defines AUTH_SUCCESS", () => {
    assert.equal(AuditEvent.AUTH_SUCCESS, "AUTH_SUCCESS");
  });

  it("defines AUTH_FAILURE", () => {
    assert.equal(AuditEvent.AUTH_FAILURE, "AUTH_FAILURE");
  });

  it("defines SESSION_CREATED", () => {
    assert.equal(AuditEvent.SESSION_CREATED, "SESSION_CREATED");
  });

  it("defines INJECTION_BLOCKED", () => {
    assert.equal(AuditEvent.INJECTION_BLOCKED, "INJECTION_BLOCKED");
  });

  it("defines RATE_LIMITED", () => {
    assert.equal(AuditEvent.RATE_LIMITED, "RATE_LIMITED");
  });
});

// ---------------------------------------------------------------------------
// logAuth
// ---------------------------------------------------------------------------
describe("logAuth", () => {
  let logs;
  const originalLog = console.log;

  beforeEach(() => {
    logs = [];
    console.log = (...args) => logs.push(args.join(" "));
  });

  afterEach(() => {
    console.log = originalLog;
  });

  it("logs AUTH_SUCCESS when success=true", () => {
    logAuth(true, undefined, "1.2.3.4");
    assert.ok(logs.some((l) => l.includes(AuditEvent.AUTH_SUCCESS)));
  });

  it("logs AUTH_FAILURE when success=false", () => {
    logAuth(false, "bad token", "1.2.3.4");
    assert.ok(logs.some((l) => l.includes(AuditEvent.AUTH_FAILURE)));
  });

  it("includes the failure reason for AUTH_FAILURE", () => {
    logAuth(false, "bad token", "1.2.3.4");
    assert.ok(logs.some((l) => l.includes("bad token")));
  });

  it("does not include 'reason' in AUTH_SUCCESS log", () => {
    logAuth(true, undefined, "1.2.3.4");
    const entry = JSON.parse(logs[0].replace("[AUDIT] ", ""));
    assert.equal(entry.reason, undefined);
  });

  it("uses '(unknown)' when IP is not provided", () => {
    logAuth(true);
    assert.ok(logs.some((l) => l.includes("(unknown)")));
  });
});

// ---------------------------------------------------------------------------
// logSession
// ---------------------------------------------------------------------------
describe("logSession", () => {
  let logs;
  const originalLog = console.log;

  beforeEach(() => {
    logs = [];
    console.log = (...args) => logs.push(args.join(" "));
  });

  afterEach(() => {
    console.log = originalLog;
  });

  it("logs the session event type", () => {
    logSession(AuditEvent.SESSION_CREATED, "abc123sessionid", "1.2.3.4");
    assert.ok(logs.some((l) => l.includes(AuditEvent.SESSION_CREATED)));
  });

  it("masks the session ID (does not log the full session ID)", () => {
    const fullId = "abcdef1234567890abcdef1234567890";
    logSession(AuditEvent.SESSION_USED, fullId, "1.2.3.4");
    const logLine = logs[0];
    assert.ok(!logLine.includes(fullId), "Full session ID should not appear in logs");
    // Should include the masked version (first 8 chars)
    assert.ok(logLine.includes("abcdef12"), "Should include first 8 chars of session ID");
  });

  it("uses '(unknown)' when IP is not provided", () => {
    logSession(AuditEvent.SESSION_DESTROYED, "some-session");
    assert.ok(logs.some((l) => l.includes("(unknown)")));
  });
});

// ---------------------------------------------------------------------------
// logAdminWrite
// ---------------------------------------------------------------------------
describe("logAdminWrite", () => {
  let logs;
  const originalLog = console.log;

  beforeEach(() => {
    logs = [];
    console.log = (...args) => logs.push(args.join(" "));
  });

  afterEach(() => {
    console.log = originalLog;
  });

  it("logs ADMIN_WRITE event for successful operation", () => {
    logAdminWrite("update-balance", true, "0xABCDEF1234567890", "1.2.3.4");
    assert.ok(logs.some((l) => l.includes(AuditEvent.ADMIN_WRITE)));
  });

  it("logs ACCESS_DENIED event for failed operation", () => {
    logAdminWrite("update-balance", false, "0xABCDEF1234567890", "1.2.3.4");
    assert.ok(logs.some((l) => l.includes(AuditEvent.ACCESS_DENIED)));
  });

  it("includes the operation name", () => {
    logAdminWrite("update-balance", true, "0xABCDEF1234567890", "1.2.3.4");
    assert.ok(logs.some((l) => l.includes("update-balance")));
  });

  it("does not log the full wallet address (masks it)", () => {
    const fullAddr = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    logAdminWrite("update-balance", true, fullAddr, "1.2.3.4");
    assert.ok(!logs.some((l) => l.includes(fullAddr)), "Full address should not appear in logs");
  });
});

// ---------------------------------------------------------------------------
// logInjectionBlocked
// ---------------------------------------------------------------------------
describe("logInjectionBlocked", () => {
  let logs;
  const originalLog = console.log;

  beforeEach(() => {
    logs = [];
    console.log = (...args) => logs.push(args.join(" "));
  });

  afterEach(() => {
    console.log = originalLog;
  });

  it("logs the INJECTION_BLOCKED event", () => {
    logInjectionBlocked("prompt injection detected", "5.6.7.8");
    assert.ok(logs.some((l) => l.includes(AuditEvent.INJECTION_BLOCKED)));
  });

  it("includes the reason in the log", () => {
    logInjectionBlocked("prompt injection detected", "5.6.7.8");
    assert.ok(logs.some((l) => l.includes("prompt injection detected")));
  });

  it("includes the IP in the log", () => {
    logInjectionBlocked("prompt injection detected", "5.6.7.8");
    assert.ok(logs.some((l) => l.includes("5.6.7.8")));
  });

  it("uses '(unknown)' when IP is not provided", () => {
    logInjectionBlocked("prompt injection detected");
    assert.ok(logs.some((l) => l.includes("(unknown)")));
  });
});
