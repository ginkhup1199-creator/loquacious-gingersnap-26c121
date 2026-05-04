"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  sanitizeString,
  sanitizeObject,
  sanitizeWalletAddress,
  escapeHtml,
} = require("../../src/security/contentSanitizer.js");

// ---------------------------------------------------------------------------
// escapeHtml
// ---------------------------------------------------------------------------
describe("escapeHtml", () => {
  it("escapes ampersand", () => {
    assert.equal(escapeHtml("a & b"), "a &amp; b");
  });

  it("escapes less-than", () => {
    assert.equal(escapeHtml("<script>"), "&lt;script&gt;");
  });

  it("escapes double quotes", () => {
    assert.equal(escapeHtml('"hello"'), "&quot;hello&quot;");
  });

  it("escapes single quotes", () => {
    assert.equal(escapeHtml("it's"), "it&#x27;s");
  });

  it("escapes forward slash", () => {
    assert.equal(escapeHtml("a/b"), "a&#x2F;b");
  });

  it("returns empty string unchanged", () => {
    assert.equal(escapeHtml(""), "");
  });

  it("handles plain text with no special chars", () => {
    assert.equal(escapeHtml("hello world"), "hello world");
  });

  it("escapes multiple special chars in one string", () => {
    assert.equal(escapeHtml('<a href="x">it\'s</a>'), "&lt;a href=&quot;x&quot;&gt;it&#x27;s&lt;&#x2F;a&gt;");
  });
});

// ---------------------------------------------------------------------------
// sanitizeString
// ---------------------------------------------------------------------------
describe("sanitizeString", () => {
  it("returns plain strings unchanged", () => {
    assert.equal(sanitizeString("hello"), "hello");
  });

  it("trims leading and trailing whitespace", () => {
    assert.equal(sanitizeString("  hello  "), "hello");
  });

  it("removes null bytes", () => {
    assert.equal(sanitizeString("hel\x00lo"), "hello");
  });

  it("truncates to default max length (1000)", () => {
    const long = "a".repeat(2000);
    assert.equal(sanitizeString(long).length, 1000);
  });

  it("truncates to custom maxLength", () => {
    const result = sanitizeString("abcdefghij", { maxLength: 5 });
    assert.equal(result, "abcde");
  });

  it("blocks javascript: scheme", () => {
    assert.equal(sanitizeString("javascript:alert(1)"), "");
  });

  it("blocks data: scheme", () => {
    assert.equal(sanitizeString("data:text/html,<h1>x</h1>"), "");
  });

  it("blocks vbscript: scheme", () => {
    assert.equal(sanitizeString("vbscript:msgbox(1)"), "");
  });

  it("blocks file: scheme", () => {
    assert.equal(sanitizeString("file:///etc/passwd"), "");
  });

  it("blocks schemes case-insensitively", () => {
    assert.equal(sanitizeString("JAVASCRIPT:alert(1)"), "");
  });

  it("HTML-escapes by default", () => {
    assert.equal(sanitizeString("<b>bold</b>"), "&lt;b&gt;bold&lt;&#x2F;b&gt;");
  });

  it("skips HTML escaping when escapeHtmlChars=false", () => {
    assert.equal(sanitizeString("<b>bold</b>", { escapeHtmlChars: false }), "<b>bold</b>");
  });

  it("converts non-string to string", () => {
    assert.equal(sanitizeString(42), "42");
  });

  it("returns empty string for null/undefined input", () => {
    assert.equal(sanitizeString(null), "");
    assert.equal(sanitizeString(undefined), "");
  });
});

// ---------------------------------------------------------------------------
// sanitizeObject
// ---------------------------------------------------------------------------
describe("sanitizeObject", () => {
  it("returns null for null input", () => {
    assert.equal(sanitizeObject(null), null);
  });

  it("returns undefined for undefined input", () => {
    assert.equal(sanitizeObject(undefined), undefined);
  });

  it("sanitizes string input", () => {
    assert.equal(sanitizeObject("<script>"), "&lt;script&gt;");
  });

  it("passes numbers through unchanged", () => {
    assert.equal(sanitizeObject(42), 42);
  });

  it("passes booleans through unchanged", () => {
    assert.equal(sanitizeObject(true), true);
    assert.equal(sanitizeObject(false), false);
  });

  it("sanitizes strings inside an array", () => {
    const result = sanitizeObject(["<a>", "ok"]);
    assert.deepEqual(result, ["&lt;a&gt;", "ok"]);
  });

  it("sanitizes string values in a plain object", () => {
    const result = sanitizeObject({ name: "<script>alert(1)</script>", count: 3 });
    assert.equal(result.count, 3);
    assert.ok(result.name.includes("&lt;"), "Should HTML-escape the value");
  });

  it("sanitizes nested objects recursively", () => {
    const input = { outer: { inner: "<img>" } };
    const result = sanitizeObject(input);
    assert.equal(result.outer.inner, "&lt;img&gt;");
  });

  it("sanitizes object keys (strips empty/unsafe keys)", () => {
    const input = { "": "value", validKey: "hello" };
    const result = sanitizeObject(input);
    assert.ok(!("" in result), "Empty key should be removed");
    assert.equal(result.validKey, "hello");
  });

  it("discards function values", () => {
    const input = { fn: () => "hello", str: "ok" };
    const result = sanitizeObject(input);
    assert.equal(result.fn, undefined);
    assert.equal(result.str, "ok");
  });

  it("sanitizes arrays of objects", () => {
    const input = [{ name: "<b>Bob</b>" }];
    const result = sanitizeObject(input);
    assert.ok(result[0].name.includes("&lt;b&gt;"));
  });
});

// ---------------------------------------------------------------------------
// sanitizeWalletAddress
// ---------------------------------------------------------------------------
describe("sanitizeWalletAddress", () => {
  it("accepts a valid Ethereum/BSC address (lowercase)", () => {
    const result = sanitizeWalletAddress("0xdac17f958d2ee523a2206206994597c13d831ec7");
    assert.equal(result.valid, true);
    assert.equal(result.address, "0xdac17f958d2ee523a2206206994597c13d831ec7");
  });

  it("accepts a valid Ethereum address (mixed case) and lowercases it", () => {
    const result = sanitizeWalletAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7");
    assert.equal(result.valid, true);
    assert.equal(result.address, "0xdac17f958d2ee523a2206206994597c13d831ec7");
  });

  it("accepts a Bitcoin bech32 address (bc1...)", () => {
    const result = sanitizeWalletAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
    assert.equal(result.valid, true);
  });

  it("accepts a Bitcoin legacy address (1...)", () => {
    const result = sanitizeWalletAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf")
    assert.equal(result.valid, true);
  });

  it("accepts a Bitcoin P2SH address (3...)", () => {
    const result = sanitizeWalletAddress("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
    assert.equal(result.valid, true);
  });

  it("accepts a Tron/Solana-style base58 address", () => {
    const result = sanitizeWalletAddress("TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9");
    assert.equal(result.valid, true);
  });

  it("rejects a non-string input", () => {
    const result = sanitizeWalletAddress(12345);
    assert.equal(result.valid, false);
  });

  it("rejects an empty string", () => {
    const result = sanitizeWalletAddress("");
    assert.equal(result.valid, false);
  });

  it("rejects a string with spaces", () => {
    const result = sanitizeWalletAddress("0xdAC17F 58D2ee523a2206206994597C13D831ec7");
    assert.equal(result.valid, false);
  });

  it("rejects an Ethereum address with wrong length", () => {
    const result = sanitizeWalletAddress("0xdAC17F958D2ee523a220"); // too short
    assert.equal(result.valid, false);
  });

  it("trims whitespace before validation", () => {
    const result = sanitizeWalletAddress("  0xdac17f958d2ee523a2206206994597c13d831ec7  ");
    assert.equal(result.valid, true);
  });
});
