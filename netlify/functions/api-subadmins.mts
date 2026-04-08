import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  persistAuditLog,
  getClientIp,
} from "../lib/security.js";
import { randomUUID, pbkdf2Sync, randomBytes, timingSafeEqual } from "crypto";

interface SubAdmin {
  id: string;
  username: string;
  passwordHash: string;
  passwordSalt: string;
  permissions: string[];
  status: "active" | "revoked";
  createdAt: string;
  revokedAt?: string;
}

const ALLOWED_PERMISSIONS = ["kyc", "chat", "withdrawals", "settings"] as const;
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEY_LEN = 64;
const PBKDF2_DIGEST = "sha512";

function hashPassword(password: string, salt: string): string {
  return pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LEN, PBKDF2_DIGEST).toString("hex");
}

function verifyPassword(password: string, salt: string, storedHash: string): boolean {
  try {
    const hash = hashPassword(password, salt);
    const hashBuf = Buffer.from(hash, "hex");
    const storedBuf = Buffer.from(storedHash, "hex");
    return hashBuf.length === storedBuf.length && timingSafeEqual(hashBuf, storedBuf);
  } catch {
    return false;
  }
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Service not configured" }, 503);
  }

  // All sub-admin management requires a master admin session
  const sessionResult = await validateAdminSession(req, store);
  if (!sessionResult.valid) {
    auditLog("AUTH_FAILURE", { operation: "subadmins", reason: sessionResult.reason, ip });
    return secureJson({ error: "Unauthorized" }, 401);
  }

  // ── GET: list sub-admins (passwords excluded) ─────────────────────────────
  if (req.method === "GET") {
    const subAdmins = ((await store.get("sub-admins", { type: "json" })) ?? []) as SubAdmin[];
    const safeList = subAdmins.map(({ passwordHash: _h, passwordSalt: _s, ...rest }) => rest);
    return secureJson(safeList, 200);
  }

  // ── POST: create or revoke sub-admins ─────────────────────────────────────
  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    const action = sanitizeString(String(body.action ?? ""), 32);

    // ── Create sub-admin ─────────────────────────────────────────────────────
    if (action === "create") {
      // Apply regex to strip non-alphanumeric/underscore chars first, then sanitize
      const rawUsername = String(body.username ?? "").replace(/[^a-zA-Z0-9_]/g, "");
      const username = sanitizeString(rawUsername, 50);
      const password = String(body.password ?? "");

      if (!username || username.length < 3) {
        return secureJson({ error: "Username must be at least 3 alphanumeric characters" }, 400);
      }
      if (!password || password.length < 8) {
        return secureJson({ error: "Password must be at least 8 characters" }, 400);
      }

      // Validate permissions
      const rawPerms = Array.isArray(body.permissions) ? body.permissions : [];
      const permissions = rawPerms.filter(
        (p): p is string => typeof p === "string" && (ALLOWED_PERMISSIONS as readonly string[]).includes(p)
      );

      const subAdmins = ((await store.get("sub-admins", { type: "json" })) ?? []) as SubAdmin[];

      // Check for duplicate username (active ones)
      const existing = subAdmins.find((s) => s.username === username && s.status === "active");
      if (existing) {
        return secureJson({ error: "A sub-admin with this username already exists" }, 409);
      }

      const salt = randomBytes(32).toString("hex");
      const passwordHash = hashPassword(password, salt);

      const newSubAdmin: SubAdmin = {
        id: randomUUID(),
        username,
        passwordHash,
        passwordSalt: salt,
        permissions,
        status: "active",
        createdAt: new Date().toISOString(),
      };

      subAdmins.unshift(newSubAdmin);
      await store.setJSON("sub-admins", subAdmins);

      await persistAuditLog("ADMIN_WRITE", {
        operation: "create-subadmin", username, permissions, ip,
      }, store);

      const { passwordHash: _h, passwordSalt: _s, ...safeAdmin } = newSubAdmin;
      return secureJson({ success: true, subAdmin: safeAdmin });
    }

    // ── Update sub-admin password ─────────────────────────────────────────────
    if (action === "update-password") {
      const username = sanitizeString(String(body.username ?? ""), 50);
      const newPassword = String(body.password ?? "");

      if (!username) return secureJson({ error: "Username required" }, 400);
      if (!newPassword || newPassword.length < 8) {
        return secureJson({ error: "New password must be at least 8 characters" }, 400);
      }

      const subAdmins = ((await store.get("sub-admins", { type: "json" })) ?? []) as SubAdmin[];
      const idx = subAdmins.findIndex((s) => s.username === username && s.status === "active");
      if (idx === -1) return secureJson({ error: "Sub-admin not found" }, 404);

      const salt = randomBytes(32).toString("hex");
      subAdmins[idx].passwordHash = hashPassword(newPassword, salt);
      subAdmins[idx].passwordSalt = salt;
      await store.setJSON("sub-admins", subAdmins);

      await persistAuditLog("ADMIN_WRITE", { operation: "update-subadmin-password", username, ip }, store);
      return secureJson({ success: true });
    }

    // ── Revoke sub-admin ────────────────────────────────────────────────────
    if (action === "revoke") {
      const username = sanitizeString(String(body.username ?? ""), 50);
      if (!username) return secureJson({ error: "Username required" }, 400);

      const subAdmins = ((await store.get("sub-admins", { type: "json" })) ?? []) as SubAdmin[];
      const idx = subAdmins.findIndex((s) => s.username === username && s.status === "active");
      if (idx === -1) return secureJson({ error: "Active sub-admin not found" }, 404);

      subAdmins[idx].status = "revoked";
      subAdmins[idx].revokedAt = new Date().toISOString();
      await store.setJSON("sub-admins", subAdmins);

      await persistAuditLog("ADMIN_WRITE", { operation: "revoke-subadmin", username, ip }, store);
      return secureJson({ success: true });
    }

    return secureJson({ error: "Invalid action" }, 400);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/subadmins",
  method: ["GET", "POST"],
};
