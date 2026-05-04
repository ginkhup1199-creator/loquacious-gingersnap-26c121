"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const {
  validateAdminToken,
  applyRateLimit,
  validateRequestBody,
} = require("../../src/middleware/apiSecurity.js");

// ---------------------------------------------------------------------------
// validateRequestBody
// ---------------------------------------------------------------------------
describe("validateRequestBody", () => {
  it("returns true for a plain object", () => {
    assert.equal(validateRequestBody({ key: "value" }), true);
  });

  it("returns true for an empty object", () => {
    assert.equal(validateRequestBody({}), true);
  });

  it("returns false for null", () => {
    assert.equal(validateRequestBody(null), false);
  });

  it("returns false for an array", () => {
    assert.equal(validateRequestBody([1, 2, 3]), false);
  });

  it("returns false for a string", () => {
    assert.equal(validateRequestBody("hello"), false);
  });

  it("returns false for a number", () => {
    assert.equal(validateRequestBody(42), false);
  });

  it("returns false for undefined", () => {
    assert.equal(validateRequestBody(undefined), false);
  });

  it("returns true for nested objects", () => {
    assert.equal(validateRequestBody({ nested: { key: "value" } }), true);
  });
});

// ---------------------------------------------------------------------------
// validateAdminToken (middleware)
// ---------------------------------------------------------------------------
describe("validateAdminToken (apiSecurity)", () => {
  beforeEach(() => {
    delete process.env.ADMIN_TOKEN;
  });

  afterEach(() => {
    delete process.env.ADMIN_TOKEN;
  });

  it("returns valid=false with 503 when ADMIN_TOKEN is not configured", () => {
    const req = new Request("https://example.com/api", {
      headers: { "X-Admin-Token": "some-token" },
    });
    const result = validateAdminToken(req);
    assert.equal(result.valid, false);
    assert.equal(result.response.status, 503);
  });

  it("returns valid=false with 401 when X-Admin-Token header is missing", () => {
    process.env.ADMIN_TOKEN = "super-secret-admin-token-32chars!!";
    const req = new Request("https://example.com/api");
    const result = validateAdminToken(req);
    assert.equal(result.valid, false);
    assert.equal(result.response.status, 401);
  });

  it("returns valid=false with 401 when token is incorrect", () => {
    process.env.ADMIN_TOKEN = "super-secret-admin-token-32chars!!";
    const req = new Request("https://example.com/api", {
      headers: { "X-Admin-Token": "wrong-token" },
    });
    const result = validateAdminToken(req);
    assert.equal(result.valid, false);
    assert.equal(result.response.status, 401);
  });

  it("returns valid=true when token matches exactly", () => {
    process.env.ADMIN_TOKEN = "super-secret-admin-token-32chars!!";
    const req = new Request("https://example.com/api", {
      headers: { "X-Admin-Token": "super-secret-admin-token-32chars!!" },
    });
    const result = validateAdminToken(req);
    assert.equal(result.valid, true);
    assert.equal(result.response, undefined);
  });

  it("returns valid=false for a token that is a prefix of the correct token", () => {
    process.env.ADMIN_TOKEN = "super-secret-admin-token";
    const req = new Request("https://example.com/api", {
      headers: { "X-Admin-Token": "super-secret" },
    });
    const result = validateAdminToken(req);
    assert.equal(result.valid, false);
  });
});

// ---------------------------------------------------------------------------
// applyRateLimit
// ---------------------------------------------------------------------------
describe("applyRateLimit", () => {
  // Use a unique IP for each test group to avoid cross-test pollution
  // since the rate limit map is module-level state.

  it("returns limited=false for the first request from a new IP", () => {
    const result = applyRateLimit("192.0.2.1");
    assert.equal(result.limited, false);
    assert.equal(result.response, undefined);
  });

  it("returns limited=false when under the rate limit", () => {
    const ip = "192.0.2.2";
    // Send 29 requests (limit is 30)
    for (let i = 0; i < 29; i++) {
      applyRateLimit(ip);
    }
    const result = applyRateLimit(ip); // 30th request should still be allowed
    assert.equal(result.limited, false);
  });

  it("returns limited=true and a 429 response after exceeding the rate limit", () => {
    const ip = "192.0.2.3";
    // Exhaust the rate limit (30 requests allowed)
    for (let i = 0; i < 30; i++) {
      applyRateLimit(ip);
    }
    // 31st request should be rate-limited
    const result = applyRateLimit(ip);
    assert.equal(result.limited, true);
    assert.ok(result.response, "Should return a Response");
    assert.equal(result.response.status, 429);
  });

  it("rate limit response contains a human-readable error message", async () => {
    const ip = "192.0.2.4";
    for (let i = 0; i <= 30; i++) {
      applyRateLimit(ip);
    }
    const result = applyRateLimit(ip);
    assert.equal(result.limited, true);
    const body = await result.response.json();
    assert.ok(body.error, "Should have an error field");
  });

  it("different IPs have independent rate limits", () => {
    const ip1 = "10.0.0.1";
    const ip2 = "10.0.0.2";

    // Exhaust ip1
    for (let i = 0; i <= 30; i++) {
      applyRateLimit(ip1);
    }
    const limited1 = applyRateLimit(ip1);
    const limited2 = applyRateLimit(ip2);

    assert.equal(limited1.limited, true);
    assert.equal(limited2.limited, false);
  });
});
