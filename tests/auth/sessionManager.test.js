"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  createSession,
  validateSession,
  markSessionUsed,
  destroySession,
  SESSION_TTL_MS,
} = require("../../src/auth/sessionManager.js");

/**
 * Creates a minimal mock of a @netlify/blobs store.
 * The store holds exactly one "session" slot.
 */
function makeStore(initialValue = undefined) {
  let stored = initialValue;
  return {
    async get(_key, opts) {
      if (stored === undefined) return null;
      return opts?.type === "json" ? structuredClone(stored) : stored;
    },
    async setJSON(_key, value) {
      stored = structuredClone(value);
    },
    async delete(_key) {
      stored = undefined;
    },
    // Helper to peek at internal state without going through the API
    _peek() {
      return stored;
    },
  };
}

// ---------------------------------------------------------------------------
// SESSION_TTL_MS constant
// ---------------------------------------------------------------------------
describe("SESSION_TTL_MS", () => {
  it("is exactly 1 hour in milliseconds", () => {
    assert.equal(SESSION_TTL_MS, 60 * 60 * 1000);
  });
});

// ---------------------------------------------------------------------------
// createSession
// ---------------------------------------------------------------------------
describe("createSession", () => {
  it("returns a sessionId and expiresAt", async () => {
    const store = makeStore();
    const result = await createSession(store);
    assert.ok(result.sessionId, "Should return a sessionId");
    assert.ok(result.expiresAt, "Should return an expiresAt timestamp");
  });

  it("sessionId is a non-empty hex string (64 hex chars for 32 bytes)", async () => {
    const store = makeStore();
    const { sessionId } = await createSession(store);
    assert.match(sessionId, /^[0-9a-f]{64}$/, "sessionId should be 64 hex chars");
  });

  it("expiresAt is an ISO date approximately 1 hour in the future", async () => {
    const store = makeStore();
    const before = Date.now();
    const { expiresAt } = await createSession(store);
    const after = Date.now();

    const expiresAtMs = new Date(expiresAt).getTime();
    assert.ok(expiresAtMs >= before + SESSION_TTL_MS - 100, "expiresAt should be ~1 hour from now");
    assert.ok(expiresAtMs <= after + SESSION_TTL_MS + 100, "expiresAt should be ~1 hour from now");
  });

  it("persists the session in the store", async () => {
    const store = makeStore();
    const { sessionId } = await createSession(store);
    const stored = store._peek();
    assert.equal(stored.sessionId, sessionId);
    assert.ok(stored.createdAt, "Should have createdAt");
    assert.equal(stored.usedAt, null, "usedAt should start as null");
  });

  it("replaces any existing session when called again", async () => {
    const store = makeStore();
    const { sessionId: first } = await createSession(store);
    const { sessionId: second } = await createSession(store);
    assert.notEqual(first, second, "Each createSession should produce a unique ID");
    // Only the second session should be stored
    const stored = store._peek();
    assert.equal(stored.sessionId, second);
  });

  it("generates unique session IDs on repeated calls", async () => {
    const store = makeStore();
    const ids = new Set();
    for (let i = 0; i < 10; i++) {
      const { sessionId } = await createSession(store);
      ids.add(sessionId);
    }
    assert.equal(ids.size, 10, "All session IDs should be unique");
  });
});

// ---------------------------------------------------------------------------
// validateSession
// ---------------------------------------------------------------------------
describe("validateSession", () => {
  it("returns valid=false when sessionId is null", async () => {
    const store = makeStore();
    const result = await validateSession(store, null);
    assert.equal(result.valid, false);
    assert.ok(result.reason);
  });

  it("returns valid=false when sessionId is not a string", async () => {
    const store = makeStore();
    const result = await validateSession(store, 12345);
    assert.equal(result.valid, false);
  });

  it("returns valid=false when there is no stored session", async () => {
    const store = makeStore(); // empty store
    const result = await validateSession(store, "any-session-id");
    assert.equal(result.valid, false);
    assert.ok(result.reason.toLowerCase().includes("no active session") || result.reason.toLowerCase().includes("invalid"));
  });

  it("returns valid=false when sessionId does not match stored session", async () => {
    const store = makeStore();
    await createSession(store);
    const result = await validateSession(store, "wrong-session-id");
    assert.equal(result.valid, false);
    assert.ok(result.reason.toLowerCase().includes("invalid"));
  });

  it("returns valid=true with the correct sessionId", async () => {
    const store = makeStore();
    const { sessionId } = await createSession(store);
    const result = await validateSession(store, sessionId);
    assert.equal(result.valid, true);
    assert.ok(result.session, "Should return the session object");
  });

  it("returns valid=false for an expired session and removes it from the store", async () => {
    const store = makeStore();
    // Manually insert an already-expired session
    const pastTime = new Date(Date.now() - 1000).toISOString();
    const expiredSession = {
      sessionId: "expired-session-id",
      expiresAt: pastTime,
      createdAt: pastTime,
      usedAt: null,
    };
    await store.setJSON("admin-session", expiredSession);

    const result = await validateSession(store, "expired-session-id");
    assert.equal(result.valid, false);
    assert.ok(result.reason.toLowerCase().includes("expired"));
    // Session should have been deleted from the store
    assert.equal(store._peek(), undefined);
  });
});

// ---------------------------------------------------------------------------
// markSessionUsed
// ---------------------------------------------------------------------------
describe("markSessionUsed", () => {
  it("sets usedAt on the stored session", async () => {
    const store = makeStore();
    const { sessionId } = await createSession(store);
    const session = store._peek();

    await markSessionUsed(store, session);

    const updated = store._peek();
    assert.ok(updated.usedAt, "usedAt should be set after markSessionUsed");
  });

  it("sets usedAt to an ISO timestamp", async () => {
    const store = makeStore();
    const { sessionId } = await createSession(store);
    const session = store._peek();

    const before = new Date().toISOString();
    await markSessionUsed(store, session);
    const after = new Date().toISOString();

    const updated = store._peek();
    assert.ok(updated.usedAt >= before, "usedAt should be >= before");
    assert.ok(updated.usedAt <= after, "usedAt should be <= after");
  });

  it("preserves other session fields", async () => {
    const store = makeStore();
    const { sessionId } = await createSession(store);
    const session = store._peek();

    await markSessionUsed(store, session);

    const updated = store._peek();
    assert.equal(updated.sessionId, sessionId);
    assert.ok(updated.expiresAt);
    assert.ok(updated.createdAt);
  });
});

// ---------------------------------------------------------------------------
// destroySession
// ---------------------------------------------------------------------------
describe("destroySession", () => {
  it("removes the session from the store", async () => {
    const store = makeStore();
    await createSession(store);
    assert.ok(store._peek(), "Session should exist before destroy");

    await destroySession(store);

    assert.equal(store._peek(), undefined, "Session should be gone after destroy");
  });

  it("does not throw when there is no session to destroy", async () => {
    const store = makeStore(); // empty store
    await assert.doesNotReject(() => destroySession(store));
  });
});
