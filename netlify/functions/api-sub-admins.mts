import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { randomBytes, scryptSync, timingSafeEqual } from "crypto";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  getClientIp,
  persistAuditLog,
  auditLog,
} from "../lib/security.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SubAdminPermissions {
  kyc: boolean;
  chat: boolean;
  withdrawals: boolean;
  settings: boolean;
}

export interface SubAdmin {
  id: string;
  username: string;
  passwordHash: string; // scrypt output, hex-encoded
  salt: string;         // random salt, hex-encoded
  permissions: SubAdminPermissions;
  createdAt: string;
  status: "active" | "revoked";
}

// Public-safe view (never includes password hash or salt)
type SubAdminPublic = Omit<SubAdmin, "passwordHash" | "salt">;

const STORE_KEY = "sub-admins";
const USERNAME_MAX_LEN = 40;
const PASSWORD_MIN_LEN = 8;
const PASSWORD_MAX_LEN = 128;
const MAX_SUB_ADMINS = 20;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateId(): string {
  return randomBytes(16).toString("hex");
}

function hashPassword(password: string, salt: string): string {
  // scrypt with recommended parameters for interactive login
  const hash = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return hash.toString("hex");
}

function verifyPassword(password: string, salt: string, storedHash: string): boolean {
  try {
    const inputHash = hashPassword(password, salt);
    const a = Buffer.from(inputHash, "hex");
    const b = Buffer.from(storedHash, "hex");
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function toPublic(admin: SubAdmin): SubAdminPublic {
  const { passwordHash: _ph, salt: _s, ...pub } = admin;
  return pub;
}

function sanitizePermissions(raw: unknown): SubAdminPermissions {
  const p = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  return {
    kyc:         Boolean(p["kyc"]),
    chat:        Boolean(p["chat"]),
    withdrawals: Boolean(p["withdrawals"]),
    settings:    Boolean(p["settings"]),
  };
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

  // All endpoints require a valid master-admin session
  const sessionResult = await validateAdminSession(req, store);
  if (!sessionResult.valid) {
    auditLog("AUTH_FAILURE", { operation: "sub-admins", reason: sessionResult.reason, ip });
    return secureJson({ error: "Unauthorized" }, 401);
  }

  // ── GET /api/sub-admins → list all sub-admins (no secrets) ──────────────
  if (req.method === "GET") {
    const all = ((await store.get(STORE_KEY, { type: "json" })) ?? []) as SubAdmin[];
    auditLog("ADMIN_READ", { operation: "list-sub-admins", ip });
    return secureJson(all.map(toPublic));
  }

  // ── POST /api/sub-admins → create | update-permissions | verify ──────────
  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    const action = String(body["action"] ?? "");

    // ── create ───────────────────────────────────────────────────────────────
    if (action === "create") {
      const username = sanitizeString(String(body["username"] ?? ""), USERNAME_MAX_LEN).trim();
      const password = String(body["password"] ?? "");

      if (!username || username.length < 3) {
        return secureJson({ error: "Username must be at least 3 characters." }, 400);
      }
      if (!/^[a-zA-Z0-9_\-]+$/.test(username)) {
        return secureJson({ error: "Username may only contain letters, numbers, underscores, and hyphens." }, 400);
      }
      if (!password || password.length < PASSWORD_MIN_LEN) {
        return secureJson({ error: `Password must be at least ${PASSWORD_MIN_LEN} characters.` }, 400);
      }
      if (password.length > PASSWORD_MAX_LEN) {
        return secureJson({ error: "Password is too long." }, 400);
      }

      const permissions = sanitizePermissions(body["permissions"]);
      const all = ((await store.get(STORE_KEY, { type: "json" })) ?? []) as SubAdmin[];

      if (all.length >= MAX_SUB_ADMINS) {
        return secureJson({ error: `Maximum of ${MAX_SUB_ADMINS} sub-admin accounts allowed.` }, 400);
      }
      if (all.some(a => a.username.toLowerCase() === username.toLowerCase())) {
        return secureJson({ error: "A sub-admin with that username already exists." }, 409);
      }

      const salt = randomBytes(32).toString("hex");
      const newAdmin: SubAdmin = {
        id:           generateId(),
        username,
        passwordHash: hashPassword(password, salt),
        salt,
        permissions,
        createdAt:    new Date().toISOString(),
        status:       "active",
      };

      all.push(newAdmin);
      await store.setJSON(STORE_KEY, all);
      await persistAuditLog("ADMIN_WRITE", { operation: "create-sub-admin", username, ip }, store);

      return secureJson({ success: true, admin: toPublic(newAdmin) }, 201);
    }

    // ── update-permissions ───────────────────────────────────────────────────
    if (action === "update-permissions") {
      const id = String(body["id"] ?? "").trim();
      if (!id) return secureJson({ error: "Missing sub-admin id." }, 400);

      const permissions = sanitizePermissions(body["permissions"]);
      const all = ((await store.get(STORE_KEY, { type: "json" })) ?? []) as SubAdmin[];
      const idx = all.findIndex(a => a.id === id);

      if (idx === -1) return secureJson({ error: "Sub-admin not found." }, 404);
      if (all[idx].status === "revoked") {
        return secureJson({ error: "Cannot update a revoked account." }, 400);
      }

      all[idx].permissions = permissions;
      await store.setJSON(STORE_KEY, all);
      await persistAuditLog("ADMIN_WRITE", { operation: "update-sub-admin-permissions", id, ip }, store);

      return secureJson({ success: true, admin: toPublic(all[idx]) });
    }

    // ── verify (check sub-admin credentials) ────────────────────────────────
    if (action === "verify") {
      const username = sanitizeString(String(body["username"] ?? ""), USERNAME_MAX_LEN).trim();
      const password = String(body["password"] ?? "");

      const all = ((await store.get(STORE_KEY, { type: "json" })) ?? []) as SubAdmin[];
      const found = all.find(a => a.username.toLowerCase() === username.toLowerCase() && a.status === "active");

      if (!found || !verifyPassword(password, found.salt, found.passwordHash)) {
        auditLog("AUTH_FAILURE", { operation: "sub-admin-verify", username, ip });
        return secureJson({ error: "Invalid credentials." }, 401);
      }

      return secureJson({ success: true, permissions: found.permissions });
    }

    return secureJson({ error: "Unknown action." }, 400);
  }

  // ── DELETE /api/sub-admins?id=<id> → revoke sub-admin ───────────────────
  if (req.method === "DELETE") {
    const url = new URL(req.url);
    const id  = url.searchParams.get("id")?.trim();
    if (!id) return secureJson({ error: "Missing id parameter." }, 400);

    const all = ((await store.get(STORE_KEY, { type: "json" })) ?? []) as SubAdmin[];
    const idx = all.findIndex(a => a.id === id);

    if (idx === -1) return secureJson({ error: "Sub-admin not found." }, 404);

    const username = all[idx].username;
    all[idx].status = "revoked";
    await store.setJSON(STORE_KEY, all);
    await persistAuditLog("ADMIN_WRITE", { operation: "revoke-sub-admin", id, username, ip }, store);

    return secureJson({ success: true });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/sub-admins",
  method: ["GET", "POST", "DELETE"],
};
