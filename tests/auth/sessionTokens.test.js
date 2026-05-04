"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");

const {
  generateSecureToken,
  createSession,
  issueOneTimeToken,
  validateAndConsumeToken,
  validateSession,
  destroySession,
  cleanExpiredSessions,
} = require("../../src/auth/sessionTokens.js");

// ---------------------------------------------------------------------------
// generateSecureToken
// ---------------------------------------------------------------------------
describe("generateSecureToken", () => {
  it("returns a hex string of default length (64 hex chars = 32 bytes)", () => {
    const token = generateSecureToken();
    assert.match(token, /^[0-9a-f]+$/);
    assert.equal(token.length, 64);
  });

  it("returns a hex string of specified byte length", () => {
    const token = generateSecureToken(16);
    assert.equal(token.length, 32); // 16 bytes = 32 hex chars
  });

  it("generates unique tokens on repeated calls", () => {
    const tokens = new Set(Array.from({ length: 20 }, () => generateSecureToken()));
    assert.equal(tokens.size, 20);
  });
});

// ---------------------------------------------------------------------------
// createSession
// ---------------------------------------------------------------------------
describe("createSession (sessionTokens)", () => {
  it("returns a sessionId and expiresAt", () => {
    const result = createSession("enterprise-1");
    assert.ok(result.sessionId, "Should have sessionId");
    assert.ok(result.expiresAt, "Should have expiresAt");
  });

  it("sessionId is a non-empty hex string", () => {
    const { sessionId } = createSession("enterprise-1");
    assert.match(sessionId, /^[0-9a-f]+$/);
    assert.ok(sessionId.length > 0);
  });

  it("expiresAt is a valid ISO date string", () => {
    const { expiresAt } = createSession("enterprise-1");
    assert.ok(!isNaN(new Date(expiresAt).getTime()), "expiresAt must be valid ISO date");
  });

  it("creates different sessionIds for different calls", () => {
    const { sessionId: a } = createSession("enterprise-1");
    const { sessionId: b } = createSession("enterprise-1");
    assert.notEqual(a, b);
  });
});

// ---------------------------------------------------------------------------
// issueOneTimeToken
// ---------------------------------------------------------------------------
describe("issueOneTimeToken", () => {
  it("returns null for a non-existent session", () => {
    const result = issueOneTimeToken("no-such-session");
    assert.equal(result, null);
  });

  it("returns a token and expiresAt for a valid session", () => {
    const { sessionId } = createSession("enterprise-1");
    const result = issueOneTimeToken(sessionId);
    assert.ok(result, "Should return a token object");
    assert.ok(result.token, "Should have a token field");
    assert.ok(result.expiresAt, "Should have an expiresAt field");
  });

  it("token is a hex string", () => {
    const { sessionId } = createSession("enterprise-1");
    const { token } = issueOneTimeToken(sessionId);
    assert.match(token, /^[0-9a-f]+$/);
  });

  it("issues unique tokens on repeated calls", () => {
    const { sessionId } = createSession("enterprise-1");
    const t1 = issueOneTimeToken(sessionId);
    const t2 = issueOneTimeToken(sessionId);
    assert.notEqual(t1.token, t2.token);
  });
});

// ---------------------------------------------------------------------------
// validateAndConsumeToken
// ---------------------------------------------------------------------------
describe("validateAndConsumeToken", () => {
  it("returns valid=false for a non-existent session", () => {
    const result = validateAndConsumeToken("no-such-session", "any-token");
    assert.equal(result.valid, false);
    assert.ok(result.reason);
  });

  it("returns valid=false when no token has been issued yet", () => {
    const { sessionId } = createSession("enterprise-1");
    // No token issued – session.tokenUsed starts as true
    const result = validateAndConsumeToken(sessionId, "any-token");
    assert.equal(result.valid, false);
    assert.ok(result.reason.toLowerCase().includes("token") || result.reason.toLowerCase().includes("request"));
  });

  it("returns valid=false for an incorrect token", () => {
    const { sessionId } = createSession("enterprise-1");
    issueOneTimeToken(sessionId);
    const result = validateAndConsumeToken(sessionId, "wrong-token-value");
    assert.equal(result.valid, false);
    assert.ok(result.reason.toLowerCase().includes("invalid"));
  });

  it("returns valid=true and enterpriseId for the correct token", () => {
    const { sessionId } = createSession("enterprise-42");
    const { token } = issueOneTimeToken(sessionId);
    const result = validateAndConsumeToken(sessionId, token);
    assert.equal(result.valid, true);
    assert.equal(result.enterpriseId, "enterprise-42");
  });

  it("token can only be used once (replay protection)", () => {
    const { sessionId } = createSession("enterprise-1");
    const { token } = issueOneTimeToken(sessionId);

    // First use should succeed
    const first = validateAndConsumeToken(sessionId, token);
    assert.equal(first.valid, true);

    // Second use of the same token must fail
    const second = validateAndConsumeToken(sessionId, token);
    assert.equal(second.valid, false);
  });

  it("returns valid=false for an empty token string", () => {
    const { sessionId } = createSession("enterprise-1");
    issueOneTimeToken(sessionId);
    const result = validateAndConsumeToken(sessionId, "");
    assert.equal(result.valid, false);
  });
});

// ---------------------------------------------------------------------------
// validateSession (read-only)
// ---------------------------------------------------------------------------
describe("validateSession (sessionTokens)", () => {
  it("returns valid=false for an unknown session", () => {
    const result = validateSession("no-such-session");
    assert.equal(result.valid, false);
    assert.ok(result.reason);
  });

  it("returns valid=true for an active session", () => {
    const { sessionId } = createSession("enterprise-1");
    const result = validateSession(sessionId);
    assert.equal(result.valid, true);
    assert.equal(result.enterpriseId, "enterprise-1");
  });

  it("does not consume a one-time token", () => {
    const { sessionId } = createSession("enterprise-1");
    const { token } = issueOneTimeToken(sessionId);

    // validateSession should not affect the token
    validateSession(sessionId);

    // Token should still be usable
    const result = validateAndConsumeToken(sessionId, token);
    assert.equal(result.valid, true);
  });
});

// ---------------------------------------------------------------------------
// destroySession (sessionTokens)
// ---------------------------------------------------------------------------
describe("destroySession (sessionTokens)", () => {
  it("makes the session invalid after destruction", () => {
    const { sessionId } = createSession("enterprise-1");
    assert.equal(validateSession(sessionId).valid, true);

    destroySession(sessionId);

    assert.equal(validateSession(sessionId).valid, false);
  });

  it("does not throw when called with a non-existent session", () => {
    assert.doesNotThrow(() => destroySession("non-existent-session-id"));
  });
});

// ---------------------------------------------------------------------------
// cleanExpiredSessions
// ---------------------------------------------------------------------------
describe("cleanExpiredSessions", () => {
  it("does not throw when there are no sessions", () => {
    assert.doesNotThrow(() => cleanExpiredSessions());
  });

  it("keeps active sessions intact", () => {
    const { sessionId } = createSession("enterprise-cleanup-test");
    cleanExpiredSessions();
    const result = validateSession(sessionId);
    assert.equal(result.valid, true);
    // Cleanup after test
    destroySession(sessionId);
  });
});
