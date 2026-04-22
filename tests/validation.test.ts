import test = require("node:test");
import assert = require("node:assert/strict");

import { isRecord, normalizeBalanceRecord, normalizeWallet, parseJsonObject, sanitizeWalletLegacy, toArray, toInteger, toNumber, toStringArray } from "../netlify/lib/validation.js";

test("normalizeWallet lowercases and sanitizes wallet input", () => {
  assert.equal(normalizeWallet("  AbC<scRipt>123  "), "abc&lt;script&gt;123");
  assert.equal(normalizeWallet(undefined), "");
});

test("sanitizeWalletLegacy preserves original case while sanitizing", () => {
  assert.equal(sanitizeWalletLegacy("  AbC<scRipt>123  "), "AbC&lt;scRipt&gt;123");
});

test("isRecord returns true only for plain objects", () => {
  assert.equal(isRecord({ wallet: "abc" }), true);
  assert.equal(isRecord(null), false);
  assert.equal(isRecord(["abc"]), false);
  assert.equal(isRecord("abc"), false);
});

test("parseJsonObject accepts object JSON bodies", async () => {
  const req = new Request("https://example.com", {
    method: "POST",
    body: JSON.stringify({ wallet: "AbC123" }),
    headers: { "Content-Type": "application/json" },
  });

  const parsed = await parseJsonObject(req);
  assert.deepEqual(parsed, { wallet: "AbC123" });
});

test("parseJsonObject rejects non-object JSON bodies", async () => {
  const req = new Request("https://example.com", {
    method: "POST",
    body: JSON.stringify(["not-an-object"]),
    headers: { "Content-Type": "application/json" },
  });

  await assert.rejects(() => parseJsonObject(req), /Request body must be a JSON object/);
});

test("toNumber returns parsed numeric values and fallback for invalid input", () => {
  assert.equal(toNumber("42.5", 0), 42.5);
  assert.equal(toNumber("not-a-number", 7), 7);
});

test("toInteger returns parsed integers and fallback for invalid input", () => {
  assert.equal(toInteger("42.5", 0), 42);
  assert.equal(toInteger(undefined, 9), 9);
});

test("toArray returns arrays and defaults non-arrays to empty arrays", () => {
  assert.deepEqual(toArray<string>(["a", "b"]), ["a", "b"]);
  assert.deepEqual(toArray<string>({ value: "a" }), []);
});

test("toStringArray keeps only string entries from unknown arrays", () => {
  assert.deepEqual(toStringArray(["a", 1, "b", null]), ["a", "b"]);
  assert.deepEqual(toStringArray("not-an-array"), []);
});

test("normalizeBalanceRecord coerces invalid balances to a safe usdt default", () => {
  assert.deepEqual(normalizeBalanceRecord({ usdt: "12.5" }), { usdt: 12.5 });
  assert.deepEqual(normalizeBalanceRecord({ usdt: -5 }), { usdt: 0 });
  assert.deepEqual(normalizeBalanceRecord(null), { usdt: 0 });
});