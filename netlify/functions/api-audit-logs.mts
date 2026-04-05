import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  auditLog,
  getClientIp,
} from "../lib/security.js";

/**
 * GET /api/audit-logs
 * Returns the last 500 persisted audit events (newest first).
 * Requires a valid admin session token (X-Session-Token header).
 */
export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  const sessionResult = await validateAdminSession(req, store);
  if (!sessionResult.valid) {
    auditLog("AUTH_FAILURE", { operation: "read-audit-logs", reason: sessionResult.reason, ip });
    return secureJson({ error: "Unauthorized" }, 401);
  }

  const logs = await store.get("audit-log", { type: "json" });
  return secureJson(logs || []);
};

export const config: Config = {
  path: "/api/audit-logs",
  method: ["GET"],
};
