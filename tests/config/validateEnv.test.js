"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const { validateEnv, getConfig } = require("../../src/config/validateEnv.js");

// ---------------------------------------------------------------------------
// Helper to safely call functions that throw
// ---------------------------------------------------------------------------
function capture(fn) {
  try {
    fn();
    return { threw: false };
  } catch (err) {
    return { threw: true, message: err.message };
  }
}

// ---------------------------------------------------------------------------
// validateEnv
// ---------------------------------------------------------------------------
describe("validateEnv", () => {
  beforeEach(() => {
    delete process.env.ADMIN_TOKEN;
  });

  afterEach(() => {
    delete process.env.ADMIN_TOKEN;
  });

  it("throws when ADMIN_TOKEN is not set", () => {
    const { threw, message } = capture(() => validateEnv());
    assert.equal(threw, true);
    assert.ok(message.includes("ADMIN_TOKEN"), "Error should mention the missing variable");
  });

  it("throws when ADMIN_TOKEN is shorter than 32 characters", () => {
    process.env.ADMIN_TOKEN = "short";
    const { threw, message } = capture(() => validateEnv());
    assert.equal(threw, true);
    assert.ok(message.toLowerCase().includes("32"), "Error should mention minimum length");
  });

  it("throws when ADMIN_TOKEN is exactly 31 characters", () => {
    process.env.ADMIN_TOKEN = "a".repeat(31);
    const { threw } = capture(() => validateEnv());
    assert.equal(threw, true);
  });

  it("does not throw when ADMIN_TOKEN is exactly 32 characters", () => {
    process.env.ADMIN_TOKEN = "a".repeat(32);
    const { threw } = capture(() => validateEnv());
    assert.equal(threw, false);
  });

  it("does not throw when ADMIN_TOKEN is longer than 32 characters", () => {
    process.env.ADMIN_TOKEN = "a".repeat(64);
    const { threw } = capture(() => validateEnv());
    assert.equal(threw, false);
  });

  it("error message lists the missing variable name", () => {
    const { message } = capture(() => validateEnv());
    assert.ok(message.includes("ADMIN_TOKEN"));
  });
});

// ---------------------------------------------------------------------------
// getConfig
// ---------------------------------------------------------------------------
describe("getConfig", () => {
  beforeEach(() => {
    delete process.env.ADMIN_TOKEN;
    delete process.env.NODE_ENV;
  });

  afterEach(() => {
    delete process.env.ADMIN_TOKEN;
    delete process.env.NODE_ENV;
  });

  it("throws when ADMIN_TOKEN is not configured", () => {
    const { threw } = capture(() => getConfig());
    assert.equal(threw, true);
  });

  it("returns adminToken and nodeEnv when ADMIN_TOKEN is valid", () => {
    process.env.ADMIN_TOKEN = "a".repeat(32);
    const config = getConfig();
    assert.equal(config.adminToken, "a".repeat(32));
    assert.ok(config.nodeEnv, "nodeEnv should be present");
  });

  it("defaults nodeEnv to 'development' when NODE_ENV is not set", () => {
    process.env.ADMIN_TOKEN = "a".repeat(32);
    const config = getConfig();
    assert.equal(config.nodeEnv, "development");
  });

  it("uses NODE_ENV when set", () => {
    process.env.ADMIN_TOKEN = "a".repeat(32);
    process.env.NODE_ENV = "production";
    const config = getConfig();
    assert.equal(config.nodeEnv, "production");
  });
});
