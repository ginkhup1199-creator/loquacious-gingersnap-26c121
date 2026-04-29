import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { createHash, randomBytes } from "crypto";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  persistAuditLog,
  getClientIp,
} from "../lib/security.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SubAdminAccount {
  username: string;
  passwordHash: string; // SHA-256 hex
  permissions: string[];
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ACCOUNTS_KEY = "subadmin-accounts";
const ALLOWED_PERMISSIONS = ["kyc", "withdrawals", "chat", "settings", "users", "trades"];

function hashPassword(password: string): string {
  return createHash("sha256").update(password).digest("hex");
}

function generateTempPassword(): string {
  // 16 bytes = 128 bits of entropy, represented as 32 hex chars
  return randomBytes(16).toString("hex");
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * /api/v2/admin-accounts — Sub-admin account management.
 * ALL methods require a valid master session (X-Session-Token).
 * Only the master admin can create, list, or revoke sub-admin accounts.
 */
export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  // All operations require a valid master session
  const sessionResult = await validateAdminSession(req, store);
  if (!sessionResult.valid) {
    auditLog("AUTH_FAILURE", { operation: "admin-accounts", reason: sessionResult.reason, ip });
    return secureJson({ error: "Unauthorized — master session required" }, 401);
  }

  // ── GET /api/v2/admin-accounts — list all sub-admin accounts ─────────────
  if (req.method === "GET") {
    const accounts = ((await store.get(ACCOUNTS_KEY, { type: "json" })) ?? []) as SubAdminAccount[];
    // Never return password hashes to the client
    const safe = accounts.map(({ username, permissions, createdAt }) => ({ username, permissions, createdAt }));
    auditLog("ADMIN_READ", { operation: "list-subadmin-accounts", count: safe.length, ip });
    return secureJson(safe);
  }

  // ── POST /api/v2/admin-accounts — create or revoke sub-admin ─────────────
  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = (await req.json()) as Record<string, unknown>;
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }

    const action = String(body.action ?? "");

    if (action === "create") {
      const rawUsername = sanitizeString(String(body.username ?? ""), 50).toLowerCase();
      if (!rawUsername || !/^[a-z0-9_-]{3,50}$/.test(rawUsername)) {
        return secureJson({ error: "Username must be 3–50 characters (a-z, 0-9, _ -)" }, 400);
      }

      // Parse permissions — only allow whitelisted values
      const rawPerms: string[] = Array.isArray(body.permissions) ? body.permissions as string[] : [];
      const permissions = rawPerms.filter((p) => typeof p === "string" && ALLOWED_PERMISSIONS.includes(p));

      const accounts = ((await store.get(ACCOUNTS_KEY, { type: "json" })) ?? []) as SubAdminAccount[];
      if (accounts.some((a) => a.username === rawUsername)) {
        return secureJson({ error: `Sub-admin '${rawUsername}' already exists` }, 409);
      }

      // Use provided password or generate a temp one
      const rawPassword = String(body.password ?? "").trim();
      const password = rawPassword.length >= 8 ? rawPassword : generateTempPassword();

      const newAccount: SubAdminAccount = {
        username: rawUsername,
        passwordHash: hashPassword(password),
        permissions,
        createdAt: new Date().toISOString(),
      };
      accounts.push(newAccount);
      await store.setJSON(ACCOUNTS_KEY, accounts);

      await persistAuditLog("ADMIN_WRITE", { operation: "create-subadmin", username: rawUsername, permissions, ip }, store);

      return secureJson({
        success: true,
        username: rawUsername,
        permissions,
        // Only returned once — master must share this with the new sub-admin
        tempPassword: rawPassword.length >= 8 ? undefined : password,
        message: rawPassword.length >= 8
          ? `Sub-admin '${rawUsername}' created.`
          : `Sub-admin '${rawUsername}' created with a temporary password. Share it now — it will not be shown again.`,
      }, 201);
    }

    if (action === "revoke") {
      const rawUsername = sanitizeString(String(body.username ?? ""), 50).toLowerCase();
      if (!rawUsername) {
        return secureJson({ error: "Username is required" }, 400);
      }

      const accounts = ((await store.get(ACCOUNTS_KEY, { type: "json" })) ?? []) as SubAdminAccount[];
      const before = accounts.length;
      const updated = accounts.filter((a) => a.username !== rawUsername);

      if (updated.length === before) {
        return secureJson({ error: `Sub-admin '${rawUsername}' not found` }, 404);
      }

      await store.setJSON(ACCOUNTS_KEY, updated);

      // Also destroy any live sub-admin session — best effort (sessions are keyed by token,
      // not by username, so we can't enumerate them here; they'll expire naturally in 1h).
      await persistAuditLog("ADMIN_WRITE", { operation: "revoke-subadmin", username: rawUsername, ip }, store);

      return secureJson({ success: true, message: `Sub-admin '${rawUsername}' revoked.` });
    }

    return secureJson({ error: "Invalid action. Use 'create' or 'revoke'." }, 400);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/v2/admin-accounts",
  method: ["GET", "POST"],
};
