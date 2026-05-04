"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const {
  validateAdminToken,
  logAdminOperation,
  unauthorizedResponse,
} = require("../../src/auth/adminAuth.js");

// ---------------------------------------------------------------------------
// validateAdminToken
// ---------------------------------------------------------------------------
describe("validateAdminToken", () => {
  beforeEach(() => {
    delete process.env.ADMIN_TOKEN;
  });

  afterEach(() => {
    delete process.env.ADMIN_TOKEN;
  });

  it("returns authorized=false when ADMIN_TOKEN env var is not set", () => {
    const result = validateAdminToken("sometoken");
    assert.equal(result.authorized, false);
    assert.ok(result.reason.toLowerCase().includes("not configured"));
  });

  it("returns authorized=false when token is null", () => {
    process.env.ADMIN_TOKEN = "correct-token-here-1234567890abcdef";
    const result = validateAdminToken(null);
    assert.equal(result.authorized, false);
    assert.ok(result.reason);
  });

  it("returns authorized=false when token is undefined", () => {
    process.env.ADMIN_TOKEN = "correct-token-here-1234567890abcdef";
    const result = validateAdminToken(undefined);
    assert.equal(result.authorized, false);
  });

  it("returns authorized=false when token is a number (not a string)", () => {
    process.env.ADMIN_TOKEN = "correct-token-here-1234567890abcdef";
    const result = validateAdminToken(12345);
    assert.equal(result.authorized, false);
  });

  it("returns authorized=false when token is incorrect", () => {
    process.env.ADMIN_TOKEN = "correct-token-here-1234567890abcdef";
    const result = validateAdminToken("wrong-token");
    assert.equal(result.authorized, false);
    assert.ok(result.reason.toLowerCase().includes("invalid"));
  });

  it("returns authorized=true when token matches", () => {
    process.env.ADMIN_TOKEN = "correct-token-here-1234567890abcdef";
    const result = validateAdminToken("correct-token-here-1234567890abcdef");
    assert.equal(result.authorized, true);
  });

  it("is case-sensitive (wrong case returns unauthorized)", () => {
    process.env.ADMIN_TOKEN = "CORRECT-TOKEN";
    const result = validateAdminToken("correct-token");
    assert.equal(result.authorized, false);
  });
});

// ---------------------------------------------------------------------------
// logAdminOperation
// ---------------------------------------------------------------------------
describe("logAdminOperation", () => {
  it("logs SUCCESS status when success=true", () => {
    const logs = [];
    const originalLog = console.log;
    console.log = (...args) => logs.push(args.join(" "));

    logAdminOperation("test operation", true);

    console.log = originalLog;
    assert.ok(logs.some((l) => l.includes("SUCCESS")));
    assert.ok(logs.some((l) => l.includes("test operation")));
  });

  it("logs DENIED status when success=false", () => {
    const logs = [];
    const originalLog = console.log;
    console.log = (...args) => logs.push(args.join(" "));

    logAdminOperation("failed operation", false);

    console.log = originalLog;
    assert.ok(logs.some((l) => l.includes("DENIED")));
  });

  it("includes a timestamp in the log", () => {
    const logs = [];
    const originalLog = console.log;
    console.log = (...args) => logs.push(args.join(" "));

    logAdminOperation("timestamp check", true);

    console.log = originalLog;
    // ISO timestamp pattern check
    assert.ok(logs.some((l) => /\d{4}-\d{2}-\d{2}T/.test(l)));
  });
});

// ---------------------------------------------------------------------------
// unauthorizedResponse
// ---------------------------------------------------------------------------
describe("unauthorizedResponse", () => {
  it("returns a Response with status 401", () => {
    const response = unauthorizedResponse("Invalid token");
    assert.equal(response.status, 401);
  });

  it("returns a JSON body with 'Unauthorized' error", async () => {
    const response = unauthorizedResponse("Invalid token");
    const body = await response.json();
    assert.equal(body.error, "Unauthorized");
  });

  it("does not expose the reason to the client", async () => {
    const response = unauthorizedResponse("Super secret internal reason");
    const body = await response.json();
    assert.ok(!JSON.stringify(body).includes("Super secret internal reason"));
  });
});
