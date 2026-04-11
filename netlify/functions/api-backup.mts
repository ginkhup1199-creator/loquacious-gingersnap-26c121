import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  auditLog,
  persistAuditLog,
  getClientIp,
} from "../lib/security.mjs";

/**
 * Netlify Blobs Backup & Restore
 *
 * GET  /api/backup         – Export all known data blobs as a JSON snapshot.
 *                            Requires admin session.
 * POST /api/backup         – Restore data from a previously exported snapshot.
 *                            Requires admin session.
 *                            Body: { snapshot: <object returned by GET> }
 *
 * The snapshot contains ONLY non-sensitive application data keys.
 * Session and OTP blobs are intentionally excluded from both export and
 * import so that a restore can never replay an old admin session.
 */

// Keys that are exportable / restorable.  Session tokens and OTPs are
// excluded so a backup file cannot be used to hijack an active session.
const BLOB_KEYS = [
  "features",
  "levels",
  "settings",
  "audit-log",
  "kyc-pending",
];

// Per-wallet key patterns are discovered dynamically during export.
// Static prefix list used for the discovery scan:
const DYNAMIC_KEY_PREFIXES = [
  "balance-",
  "kyc-",
  "withdrawal-",
  "user-",
  "trade-control-",
  "deposit-address-",
];

// Maximum keys scanned per prefix to bound export duration.
const MAX_KEYS_PER_PREFIX = 500;

// Metadata fields injected into every snapshot (not data keys).
const SNAPSHOT_METADATA_KEYS = 2; // "exportedAt" and "version"

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  const sessionResult = await validateAdminSession(req, store);
  if (!sessionResult.valid) {
    auditLog("AUTH_FAILURE", { operation: `backup-${req.method.toLowerCase()}`, reason: sessionResult.reason, ip });
    return secureJson({ error: "Unauthorized" }, 401);
  }

  // ── GET: export snapshot ─────────────────────────────────────────────────
  if (req.method === "GET") {
    const snapshot: Record<string, unknown> = {
      exportedAt: new Date().toISOString(),
      version: "1",
    };

    // Export well-known static keys
    for (const key of BLOB_KEYS) {
      try {
        const value = await store.get(key, { type: "json" });
        if (value !== null) snapshot[key] = value;
      } catch {
        // Skip missing or unreadable keys
      }
    }

    // Discover and export per-entity dynamic keys
    let truncated = false;
    for (const prefix of DYNAMIC_KEY_PREFIXES) {
      try {
        const listed = await store.list({ prefix });
        if (listed.blobs.length > MAX_KEYS_PER_PREFIX) truncated = true;
        const blobs = listed.blobs.slice(0, MAX_KEYS_PER_PREFIX);
        for (const blob of blobs) {
          // Skip session/OTP keys even if accidentally matched
          if (blob.key === "admin-session" || blob.key === "admin-otp") continue;
          try {
            const value = await store.get(blob.key, { type: "json" });
            if (value !== null) snapshot[blob.key] = value;
          } catch {
            // Skip unreadable entries
          }
        }
      } catch {
        // list() not available or prefix empty — skip
      }
    }

    const dataKeyCount = Object.keys(snapshot).length - SNAPSHOT_METADATA_KEYS;
    if (truncated) snapshot["_truncated"] = true;
    await persistAuditLog("ADMIN_WRITE", { operation: "backup-export", keyCount: dataKeyCount, truncated, ip }, store);
    return secureJson(snapshot);
  }

  // ── POST: restore snapshot ───────────────────────────────────────────────
  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }

    const snapshot = body.snapshot;
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
      return secureJson({ error: "Missing or invalid 'snapshot' field" }, 400);
    }

    const data = snapshot as Record<string, unknown>;

    // Validate snapshot version
    if (data["version"] !== "1") {
      return secureJson({ error: "Unsupported snapshot version" }, 400);
    }

    // Build allow-list of restorable keys (static + dynamic prefix matches)
    const allowedPrefixes = [...DYNAMIC_KEY_PREFIXES];
    const isRestorableKey = (key: string): boolean => {
      if (BLOB_KEYS.includes(key)) return true;
      if (key === "exportedAt" || key === "version") return false;
      // Session and OTP keys are never restored
      if (key === "admin-session" || key === "admin-otp") return false;
      return allowedPrefixes.some(p => key.startsWith(p));
    };

    let restored = 0;
    const errors: string[] = [];

    for (const [key, value] of Object.entries(data)) {
      if (!isRestorableKey(key)) continue;
      if (value === null || value === undefined) continue;
      try {
        await store.setJSON(key, value);
        restored++;
      } catch {
        errors.push(key);
        console.error(`[AUDIT] {"event":"BACKUP_RESTORE_KEY_ERROR","error":"store.setJSON failed"}`);
      }
    }

    await persistAuditLog("ADMIN_WRITE", { operation: "backup-restore", restored, errors: errors.length, ip }, store);

    if (errors.length > 0) {
      return secureJson(
        { restored, failed: errors.length, failedKeys: errors, warning: "Some keys could not be restored" },
        207
      );
    }

    return secureJson({ restored, message: "Snapshot restored successfully" });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/backup",
  method: ["GET", "POST"],
};
