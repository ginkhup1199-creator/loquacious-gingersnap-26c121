/**
 * /api/admin-accounts — Sub-admin account management and sub-admin login.
 *
 * Master-only write operations (require master X-Session-Token):
 *   POST { action: 'create', username, password, permissions }
 *   POST { action: 'revoke', username }
 *   GET  (list all sub-admin accounts)
 *
 * Public (no session required):
 *   POST { action: 'login', username, password }  → returns sub-admin sessionId + permissions
 *
 * Sub-admin self-service (require sub-admin X-Session-Token):
 *   DELETE  → logout (destroy sub-admin session)
 */

import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { createHash, randomBytes, timingSafeEqual } from "crypto";
import {
  validateAdminSession,
  validateAnyAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  persistAuditLog,
  getClientIp,
  checkRateLimit,
  rateLimitExceededResponse,
} from "../lib/security.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SUB_ADMIN_SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour
const SUB_ADMIN_ACCOUNTS_KEY   = "subadmin-accounts";
const ALLOWED_PERMISSIONS      = ["kyc", "chat", "withdrawals", "settings"] as const;
type Permission = typeof ALLOWED_PERMISSIONS[number];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SubAdminAccount {
  username: string;
  passwordHash: string; // SHA-256 hex
  permissions: Permission[];
  createdAt: string;
  createdBy: string;
  active: boolean;
}

interface SubAdminSession {
  sessionId: string;
  username: string;
  permissions: Permission[];
  expiresAt: string;
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hashPassword(password: string): string {
  return createHash("sha256").update(password).digest("hex");
}

function generateSessionId(): string {
  return randomBytes(32).toString("hex");
}

function timingSafeCompare(a: string, b: string): boolean {
  try {
    const maxLen = Math.max(a.length, b.length);
    const bufA = Buffer.alloc(maxLen);
    const bufB = Buffer.alloc(maxLen);
    Buffer.from(a).copy(bufA);
    Buffer.from(b).copy(bufB);
    return a.length === b.length && timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

function sanitizeUsername(raw: unknown): string {
  const s = sanitizeString(raw, 32);
  // Allow only alphanumerics, underscores, and hyphens
  return s.replace(/[^a-zA-Z0-9_-]/g, "");
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip    = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Server not configured" }, 503);
  }

  // ── Rate limiting ─────────────────────────────────────────────────────────
  const rl = checkRateLimit(`admin-accounts:${ip}`);
  if (!rl.allowed) {
    return rateLimitExceededResponse(rl.retryAfterMs);
  }

  // ── GET /api/admin-accounts — list sub-admin accounts (master only) ───────
  if (req.method === "GET") {
    const masterResult = await validateAdminSession(req, store);
    if (!masterResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "list-subadmins", reason: masterResult.reason, ip });
      return secureJson({ error: "Unauthorized. Master session required." }, 401);
    }

    const accounts = ((await store.get(SUB_ADMIN_ACCOUNTS_KEY, { type: "json" })) ?? []) as SubAdminAccount[];
    // Strip password hashes before returning
    const safe = accounts.map(({ passwordHash: _, ...rest }) => rest);
    return secureJson(safe);
  }

  // ── POST /api/admin-accounts ──────────────────────────────────────────────
  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    const action = String(body.action ?? "");

    // ── action: login — sub-admin username + password ─────────────────────
    if (action === "login") {
      const username    = sanitizeUsername(body.username);
      const rawPassword = String(body.password ?? "");

      if (!username || !rawPassword) {
        return secureJson({ error: "Username and password are required." }, 400);
      }

      const accounts = ((await store.get(SUB_ADMIN_ACCOUNTS_KEY, { type: "json" })) ?? []) as SubAdminAccount[];
      const account  = accounts.find((a) => a.username === username && a.active);

      // Constant-time path: always compare even when account not found (use a dummy hash)
      const expectedHash = account?.passwordHash ?? "0".repeat(64);
      const inputHash    = hashPassword(rawPassword);
      const match        = timingSafeCompare(inputHash, expectedHash) && !!account;

      if (!match) {
        console.warn(`[AUDIT] {"event":"SUBADMIN_LOGIN_FAILED","username":"${username}","ip":"${ip}"}`);
        return secureJson({ error: "Invalid username or password." }, 401);
      }

      // Create sub-admin session
      const sessionId  = generateSessionId();
      const expiresAt  = new Date(Date.now() + SUB_ADMIN_SESSION_TTL_MS).toISOString();
      const session: SubAdminSession = {
        sessionId,
        username,
        permissions: account.permissions,
        expiresAt,
        createdAt: new Date().toISOString(),
      };
      await store.setJSON(`subadmin-session-${sessionId}`, session);

      console.log(`[AUDIT] {"event":"SUBADMIN_LOGIN_SUCCESS","username":"${username}","ip":"${ip}"}`);
      return secureJson(
        { sessionId, expiresAt, role: "subadmin", permissions: account.permissions, username },
        201
      );
    }

    // ── action: create — create sub-admin account (master only) ───────────
    if (action === "create") {
      const masterResult = await validateAdminSession(req, store);
      if (!masterResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "create-subadmin", reason: masterResult.reason, ip });
        return secureJson({ error: "Unauthorized. Master session required." }, 401);
      }

      const username    = sanitizeUsername(body.username);
      const rawPassword = String(body.password ?? "").trim();
      const rawPerms    = Array.isArray(body.permissions) ? body.permissions : [];
      const permissions = rawPerms
        .map((p: unknown) => String(p))
        .filter((p): p is Permission => (ALLOWED_PERMISSIONS as readonly string[]).includes(p));

      if (!username || username.length < 3) {
        return secureJson({ error: "Username must be at least 3 characters (a-z, 0-9, _, -)." }, 400);
      }
      if (rawPassword.length < 8) {
        return secureJson({ error: "Password must be at least 8 characters." }, 400);
      }
      if (permissions.length === 0) {
        return secureJson({ error: "At least one permission must be assigned." }, 400);
      }

      const accounts = ((await store.get(SUB_ADMIN_ACCOUNTS_KEY, { type: "json" })) ?? []) as SubAdminAccount[];
      if (accounts.find((a) => a.username === username)) {
        return secureJson({ error: `Username '${username}' already exists.` }, 409);
      }

      const newAccount: SubAdminAccount = {
        username,
        passwordHash: hashPassword(rawPassword),
        permissions,
        createdAt: new Date().toISOString(),
        createdBy: "master",
        active: true,
      };
      accounts.push(newAccount);
      await store.setJSON(SUB_ADMIN_ACCOUNTS_KEY, accounts);

      await persistAuditLog("ADMIN_WRITE", { operation: "create-subadmin", username, permissions, ip }, store);

      const { passwordHash: _, ...safeAccount } = newAccount;
      return secureJson({ created: true, account: safeAccount }, 201);
    }

    // ── action: revoke — deactivate sub-admin account (master only) ────────
    if (action === "revoke") {
      const masterResult = await validateAdminSession(req, store);
      if (!masterResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "revoke-subadmin", reason: masterResult.reason, ip });
        return secureJson({ error: "Unauthorized. Master session required." }, 401);
      }

      const username = sanitizeUsername(body.username);
      if (!username) {
        return secureJson({ error: "Username is required." }, 400);
      }

      const accounts = ((await store.get(SUB_ADMIN_ACCOUNTS_KEY, { type: "json" })) ?? []) as SubAdminAccount[];
      const idx = accounts.findIndex((a) => a.username === username);
      if (idx === -1) {
        return secureJson({ error: "Account not found." }, 404);
      }

      accounts[idx].active = false;
      await store.setJSON(SUB_ADMIN_ACCOUNTS_KEY, accounts);

      await persistAuditLog("ADMIN_WRITE", { operation: "revoke-subadmin", username, ip }, store);
      return secureJson({ revoked: true, username });
    }

    return secureJson({ error: "Unknown action." }, 400);
  }

  // ── DELETE /api/admin-accounts — logout sub-admin ─────────────────────────
  if (req.method === "DELETE") {
    const sessionId = req.headers.get("X-Session-Token");
    if (sessionId) {
      const sessionResult = await validateAnyAdminSession(req, store);
      if (sessionResult.valid && sessionResult.role === "subadmin") {
        await store.delete(`subadmin-session-${sessionId}`).catch(() => {});
        console.log(`[AUDIT] {"event":"SUBADMIN_LOGOUT","username":"${sessionResult.username}","ip":"${ip}"}`);
      }
    }
    return secureJson({ message: "Logged out" });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/admin-accounts",
  method: ["GET", "POST", "DELETE"],
};
