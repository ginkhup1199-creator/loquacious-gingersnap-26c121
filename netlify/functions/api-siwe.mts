/**
 * Sign-In with Ethereum (SIWE / EIP-4361) endpoints.
 *
 * GET  /api/v2/siwe/nonce?wallet=0x...   – issue a fresh one-time nonce for a wallet
 * POST /api/v2/siwe/verify               – verify the signed SIWE message and open a
 *                                          wallet session stored in @netlify/blobs
 * DELETE /api/v2/siwe/session            – sign out (invalidate the session)
 * GET  /api/v2/siwe/session              – check whether the current session is valid
 */

import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { verifyMessage } from "ethers";
import {
  secureJson,
  sanitizeString,
  auditLog,
  getClientIp,
  checkRateLimit,
  rateLimitExceededResponse,
} from "../lib/security.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Nonces expire after 5 minutes (300 000 ms). */
const NONCE_TTL_MS = 5 * 60 * 1000;
/** Wallet sessions expire after 24 hours. */
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
/** App name embedded in the SIWE message. */
const APP_NAME = "NexusTrade";
/** App URI (update with actual domain). */
const APP_URI = process.env.APP_URL ?? "https://nexustrade.website";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomHex(bytes = 16): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Normalise an Ethereum address to lowercase hex. */
function normaliseAddress(raw: string): string | null {
  const trimmed = raw.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(trimmed)) return null;
  return trimmed.toLowerCase();
}

/** Build a simple EIP-4361–style human-readable message. */
function buildSiweMessage(wallet: string, nonce: string, issuedAt: string): string {
  return (
    `${APP_NAME} wants you to sign in with your Ethereum account:\n` +
    `${wallet}\n\n` +
    `Sign in to ${APP_NAME}\n\n` +
    `URI: ${APP_URI}\n` +
    `Version: 1\n` +
    `Nonce: ${nonce}\n` +
    `Issued At: ${issuedAt}`
  );
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export default async (req: Request, context: Context) => {
  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Service not configured" }, 503);
  }

  const store = getStore({ name: "siwe-sessions", consistency: "strong" });
  const ip = getClientIp(context);
  const url = new URL(req.url);

  // ── Rate limit all SIWE endpoints ──────────────────────────────────────────
  const rl = checkRateLimit(ip);
  if (!rl.allowed) {
    return rateLimitExceededResponse(rl.retryAfterMs);
  }

  // ── GET /api/v2/siwe/nonce ─────────────────────────────────────────────────
  if (req.method === "GET" && url.pathname.endsWith("/nonce")) {
    const rawWallet = url.searchParams.get("wallet") ?? "";
    const wallet = normaliseAddress(sanitizeString(rawWallet, 42));
    if (!wallet) {
      return secureJson({ error: "Invalid or missing EVM wallet address" }, 400);
    }

    const nonce = randomHex(16);
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + NONCE_TTL_MS).toISOString();

    await store.setJSON(`nonce-${wallet}`, { nonce, issuedAt, expiresAt });
    auditLog("SIWE_NONCE_ISSUED", { wallet: wallet.slice(0, 10) + "…", ip });

    const message = buildSiweMessage(wallet, nonce, issuedAt);
    return secureJson({ nonce, message, expiresAt });
  }

  // ── GET /api/v2/siwe/session ───────────────────────────────────────────────
  if (req.method === "GET" && url.pathname.endsWith("/session")) {
    const sessionId = req.headers.get("X-Wallet-Session");
    if (!sessionId) {
      return secureJson({ valid: false, reason: "No session token" }, 401);
    }

    const session = await store.get(`session-${sanitizeString(sessionId, 64)}`, {
      type: "json",
    }) as { wallet: string; expiresAt: string } | null;

    if (!session) {
      return secureJson({ valid: false, reason: "Session not found" }, 401);
    }
    if (new Date(session.expiresAt).getTime() < Date.now()) {
      try {
        await store.delete(`session-${sanitizeString(sessionId, 64)}`);
      } catch { /* best effort */ }
      return secureJson({ valid: false, reason: "Session expired" }, 401);
    }

    return secureJson({ valid: true, wallet: session.wallet });
  }

  // ── POST /api/v2/siwe/verify ───────────────────────────────────────────────
  if (req.method === "POST" && url.pathname.endsWith("/verify")) {
    let body: Record<string, unknown>;
    try {
      body = await req.json() as Record<string, unknown>;
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }

    const rawWallet = sanitizeString(String(body.wallet ?? ""), 42);
    const wallet = normaliseAddress(rawWallet);
    if (!wallet) {
      return secureJson({ error: "Invalid EVM wallet address" }, 400);
    }

    const signature = sanitizeString(String(body.signature ?? ""), 132);
    if (!signature || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
      return secureJson({ error: "Invalid signature format" }, 400);
    }

    // Load and validate the stored nonce
    const stored = await store.get(`nonce-${wallet}`, { type: "json" }) as
      | { nonce: string; issuedAt: string; expiresAt: string }
      | null;

    if (!stored) {
      return secureJson({ error: "No active nonce for this wallet. Request a new nonce first." }, 400);
    }
    if (new Date(stored.expiresAt).getTime() < Date.now()) {
      try { await store.delete(`nonce-${wallet}`); } catch { /* best effort */ }
      return secureJson({ error: "Nonce expired. Request a new nonce." }, 400);
    }

    // Reconstruct the exact message that was shown to the user
    const expectedMessage = buildSiweMessage(wallet, stored.nonce, stored.issuedAt);

    // Verify the signature using ethers
    let recovered: string;
    try {
      recovered = verifyMessage(expectedMessage, signature).toLowerCase();
    } catch {
      auditLog("SIWE_VERIFY_ERROR", { wallet: wallet.slice(0, 10) + "…", ip, reason: "signature recovery failed" });
      return secureJson({ error: "Signature verification failed" }, 400);
    }

    if (recovered !== wallet) {
      auditLog("SIWE_VERIFY_MISMATCH", {
        wallet: wallet.slice(0, 10) + "…",
        recovered: recovered.slice(0, 10) + "…",
        ip,
      });
      return secureJson({ error: "Signature does not match wallet address" }, 401);
    }

    // Consume the nonce (one-time use)
    try { await store.delete(`nonce-${wallet}`); } catch { /* best effort */ }

    // Create a wallet session
    const sessionId = randomHex(32);
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    await store.setJSON(`session-${sessionId}`, {
      sessionId,
      wallet,
      createdAt: new Date().toISOString(),
      expiresAt,
      ip,
    });

    auditLog("SIWE_LOGIN_SUCCESS", { wallet: wallet.slice(0, 10) + "…", ip });
    return secureJson({ success: true, sessionId, wallet, expiresAt });
  }

  // ── DELETE /api/v2/siwe/session ────────────────────────────────────────────
  if (req.method === "DELETE" && url.pathname.endsWith("/session")) {
    const sessionId = req.headers.get("X-Wallet-Session");
    if (sessionId) {
      try {
        await store.delete(`session-${sanitizeString(sessionId, 64)}`);
      } catch { /* best effort */ }
    }
    auditLog("SIWE_LOGOUT", { ip });
    return secureJson({ success: true });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: [
    "/api/v2/siwe/nonce",
    "/api/v2/siwe/verify",
    "/api/v2/siwe/session",
  ],
  method: ["GET", "POST", "DELETE"],
};
