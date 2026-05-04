"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  getSecurityHeaders,
  applySecurityHeaders,
  secureJsonResponse,
} = require("../../src/config/securityHeaders.js");

// ---------------------------------------------------------------------------
// getSecurityHeaders
// ---------------------------------------------------------------------------
describe("getSecurityHeaders", () => {
  it("returns an object", () => {
    const headers = getSecurityHeaders();
    assert.equal(typeof headers, "object");
    assert.ok(headers !== null);
  });

  it("includes X-Content-Type-Options: nosniff", () => {
    const headers = getSecurityHeaders();
    assert.equal(headers["X-Content-Type-Options"], "nosniff");
  });

  it("includes X-Frame-Options: DENY", () => {
    const headers = getSecurityHeaders();
    assert.equal(headers["X-Frame-Options"], "DENY");
  });

  it("includes X-XSS-Protection header", () => {
    const headers = getSecurityHeaders();
    assert.ok(headers["X-XSS-Protection"], "Should have X-XSS-Protection");
  });

  it("includes Referrer-Policy", () => {
    const headers = getSecurityHeaders();
    assert.ok(headers["Referrer-Policy"], "Should have Referrer-Policy");
  });

  it("includes Permissions-Policy", () => {
    const headers = getSecurityHeaders();
    assert.ok(headers["Permissions-Policy"], "Should have Permissions-Policy");
  });

  it("includes Strict-Transport-Security with max-age", () => {
    const headers = getSecurityHeaders();
    assert.ok(
      headers["Strict-Transport-Security"]?.includes("max-age"),
      "HSTS should specify max-age"
    );
  });

  it("includes Content-Security-Policy", () => {
    const headers = getSecurityHeaders();
    assert.ok(headers["Content-Security-Policy"], "Should have CSP");
  });

  it("sets Cache-Control to no-store by default (cache=false)", () => {
    const headers = getSecurityHeaders();
    assert.ok(
      headers["Cache-Control"]?.includes("no-store"),
      "Default should prevent caching"
    );
  });

  it("sets Pragma: no-cache by default", () => {
    const headers = getSecurityHeaders();
    assert.ok(headers["Pragma"]?.includes("no-cache"));
  });

  it("omits Cache-Control when cache=true", () => {
    const headers = getSecurityHeaders({ cache: true });
    assert.equal(headers["Cache-Control"], undefined);
  });

  it("omits Pragma when cache=true", () => {
    const headers = getSecurityHeaders({ cache: true });
    assert.equal(headers["Pragma"], undefined);
  });

  it("CSP includes default-src 'self'", () => {
    const headers = getSecurityHeaders();
    assert.ok(headers["Content-Security-Policy"].includes("default-src 'self'"));
  });

  it("CSP includes frame-ancestors 'none' to prevent clickjacking", () => {
    const headers = getSecurityHeaders();
    assert.ok(headers["Content-Security-Policy"].includes("frame-ancestors 'none'"));
  });
});

// ---------------------------------------------------------------------------
// applySecurityHeaders
// ---------------------------------------------------------------------------
describe("applySecurityHeaders", () => {
  it("adds security headers to a Headers instance", () => {
    const headers = new Headers();
    applySecurityHeaders(headers);
    assert.equal(headers.get("X-Content-Type-Options"), "nosniff");
    assert.equal(headers.get("X-Frame-Options"), "DENY");
  });

  it("respects cache option", () => {
    const noCache = new Headers();
    applySecurityHeaders(noCache, { cache: false });
    assert.ok(noCache.get("Cache-Control")?.includes("no-store"));

    const withCache = new Headers();
    applySecurityHeaders(withCache, { cache: true });
    assert.equal(withCache.get("Cache-Control"), null);
  });

  it("does not overwrite headers that were not set by security headers", () => {
    const headers = new Headers({ "Custom-Header": "custom-value" });
    applySecurityHeaders(headers);
    assert.equal(headers.get("Custom-Header"), "custom-value");
  });
});

// ---------------------------------------------------------------------------
// secureJsonResponse
// ---------------------------------------------------------------------------
describe("secureJsonResponse", () => {
  it("returns a 200 response by default", () => {
    const res = secureJsonResponse({ ok: true });
    assert.equal(res.status, 200);
  });

  it("uses a custom status when provided", () => {
    const res = secureJsonResponse({ error: "Not Found" }, { status: 404 });
    assert.equal(res.status, 404);
  });

  it("body serializes the provided value as JSON", async () => {
    const res = secureJsonResponse({ message: "hello" });
    const body = await res.json();
    assert.deepEqual(body, { message: "hello" });
  });

  it("response has Content-Type application/json", () => {
    const res = secureJsonResponse({ ok: true });
    assert.ok(
      res.headers.get("Content-Type")?.includes("application/json"),
      "Should be JSON content-type"
    );
  });

  it("response has X-Content-Type-Options: nosniff", () => {
    const res = secureJsonResponse({ ok: true });
    assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
  });

  it("response has X-Frame-Options: DENY", () => {
    const res = secureJsonResponse({ ok: true });
    assert.equal(res.headers.get("X-Frame-Options"), "DENY");
  });

  it("response has no-store Cache-Control by default", () => {
    const res = secureJsonResponse({ ok: true });
    assert.ok(res.headers.get("Cache-Control")?.includes("no-store"));
  });

  it("omits Cache-Control when cache=true", () => {
    const res = secureJsonResponse({ ok: true }, { cache: true });
    assert.equal(res.headers.get("Cache-Control"), null);
  });
});
