"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const {
  validateEnterpriseToken,
  isTeamAccessAttempt,
  forbiddenResponse,
} = require("../../src/auth/enterpriseAuth.js");

// ---------------------------------------------------------------------------
// isTeamAccessAttempt
// ---------------------------------------------------------------------------
describe("isTeamAccessAttempt", () => {
  it("detects 'team_' prefix", () => {
    assert.equal(isTeamAccessAttempt("team_alpha_token"), true);
  });

  it("detects 'group_' prefix", () => {
    assert.equal(isTeamAccessAttempt("group_operations_key"), true);
  });

  it("detects 'shared_' prefix", () => {
    assert.equal(isTeamAccessAttempt("shared_secret"), true);
  });

  it("detects 'org_' prefix", () => {
    assert.equal(isTeamAccessAttempt("org_admin_key"), true);
  });

  it("detects 'department_' prefix", () => {
    assert.equal(isTeamAccessAttempt("department_finance"), true);
  });

  it("detects 'role_user' prefix", () => {
    assert.equal(isTeamAccessAttempt("role_user_token"), true);
  });

  it("detects 'role_viewer' prefix", () => {
    assert.equal(isTeamAccessAttempt("role_viewer_key"), true);
  });

  it("detects 'role_editor' prefix", () => {
    assert.equal(isTeamAccessAttempt("role_editor_key"), true);
  });

  it("detects team patterns case-insensitively", () => {
    assert.equal(isTeamAccessAttempt("TEAM_alpha"), true);
    assert.equal(isTeamAccessAttempt("Group_beta"), true);
  });

  it("returns false for a normal admin token", () => {
    assert.equal(isTeamAccessAttempt("my-super-secret-admin-token"), false);
  });

  it("returns false for an empty string", () => {
    assert.equal(isTeamAccessAttempt(""), false);
  });

  it("returns false for a hex token", () => {
    assert.equal(isTeamAccessAttempt("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"), false);
  });
});

// ---------------------------------------------------------------------------
// validateEnterpriseToken
// ---------------------------------------------------------------------------
describe("validateEnterpriseToken", () => {
  beforeEach(() => {
    delete process.env.ADMIN_TOKEN;
  });

  afterEach(() => {
    delete process.env.ADMIN_TOKEN;
  });

  it("returns authorized=false when ADMIN_TOKEN is not set", () => {
    const result = validateEnterpriseToken("sometoken");
    assert.equal(result.authorized, false);
    assert.ok(result.reason.toLowerCase().includes("not configured"));
  });

  it("returns authorized=false when token is null", () => {
    process.env.ADMIN_TOKEN = "super-secret-enterprise-token-xyz";
    const result = validateEnterpriseToken(null);
    assert.equal(result.authorized, false);
  });

  it("returns authorized=false when token is an empty string", () => {
    process.env.ADMIN_TOKEN = "super-secret-enterprise-token-xyz";
    const result = validateEnterpriseToken("   ");
    assert.equal(result.authorized, false);
  });

  it("returns authorized=false when token is a number (not string)", () => {
    process.env.ADMIN_TOKEN = "super-secret-enterprise-token-xyz";
    const result = validateEnterpriseToken(12345);
    assert.equal(result.authorized, false);
  });

  it("returns authorized=false for a team-pattern token", () => {
    process.env.ADMIN_TOKEN = "super-secret-enterprise-token-xyz";
    const result = validateEnterpriseToken("team_alpha_key");
    assert.equal(result.authorized, false);
    assert.ok(result.reason.toLowerCase().includes("team"));
  });

  it("returns authorized=false for a wrong token", () => {
    process.env.ADMIN_TOKEN = "super-secret-enterprise-token-xyz";
    const result = validateEnterpriseToken("wrong-token");
    assert.equal(result.authorized, false);
    assert.ok(result.reason.toLowerCase().includes("invalid"));
  });

  it("returns authorized=true for the correct token", () => {
    process.env.ADMIN_TOKEN = "super-secret-enterprise-token-xyz";
    const result = validateEnterpriseToken("super-secret-enterprise-token-xyz");
    assert.equal(result.authorized, true);
  });

  it("returns authorized=false for a token that is a substring of the real token", () => {
    process.env.ADMIN_TOKEN = "super-secret-enterprise-token-xyz";
    const result = validateEnterpriseToken("super-secret");
    assert.equal(result.authorized, false);
  });

  it("returns authorized=false for a token that has the real token appended with extra chars", () => {
    process.env.ADMIN_TOKEN = "super-secret";
    const result = validateEnterpriseToken("super-secret-extra");
    assert.equal(result.authorized, false);
  });

  it("is case-sensitive", () => {
    process.env.ADMIN_TOKEN = "MySecretToken";
    const result = validateEnterpriseToken("mysecrettoken");
    assert.equal(result.authorized, false);
  });
});

// ---------------------------------------------------------------------------
// forbiddenResponse
// ---------------------------------------------------------------------------
describe("forbiddenResponse", () => {
  it("returns a Response with status 403", () => {
    const response = forbiddenResponse("test detail");
    assert.equal(response.status, 403);
  });

  it("returns a JSON body with a forbidden error message", async () => {
    const response = forbiddenResponse("test detail");
    const body = await response.json();
    assert.ok(body.error, "Should have an error field");
    assert.ok(body.error.toLowerCase().includes("forbidden") || body.error.toLowerCase().includes("enterprise"));
  });

  it("does not expose the internal detail to the client", async () => {
    const response = forbiddenResponse("super-secret-internal-reason");
    const body = await response.json();
    assert.ok(!JSON.stringify(body).includes("super-secret-internal-reason"));
  });

  it("works when called without a detail argument", () => {
    const response = forbiddenResponse();
    assert.equal(response.status, 403);
  });
});
