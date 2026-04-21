import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  auditLog,
  persistAuditLog,
  revokeAllSessions,
  revokeSession,
  getClientIp,
} from "../lib/security.js";

/**
 * GET /api/admin?action=stats
 * Returns system statistics for the admin dashboard.
 * Requires a valid X-Session-Token header.
 */
export default async (req: Request, context: Context) => {
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  const store = getStore({ name: "app-data", consistency: "strong" });
  const action = new URL(req.url).searchParams.get("action") || "stats";

  const sessionResult = await validateAdminSession(req, store);
  if (!sessionResult.valid) {
    auditLog("AUTH_FAILURE", { operation: action === "revoke-all" ? "admin-revoke-all" : "admin-stats", reason: sessionResult.reason, ip });
    return secureJson({ error: "Unauthorized" }, 401);
  }

  if (action === "revoke-all") {
    const currentSessionId = req.headers.get("X-Session-Token") || "";
    const revokedBefore = await revokeAllSessions(store);
    if (currentSessionId) await revokeSession(currentSessionId, store);
    await persistAuditLog("ADMIN_WRITE", { operation: "admin-revoke-all", revoked: true, revokedBefore, ip }, store);
    return secureJson({ success: true, revokedBefore });
  }

  const [allUsers, withdrawals] = await Promise.all([
    store.get("all-users", { type: "json" }) as Promise<unknown[]>,
    store.get("withdrawals", { type: "json" }) as Promise<unknown[]>,
  ]);

  const pendingWithdrawals = ((withdrawals || []) as Array<{ status: string }>)
    .filter((w) => w.status === "Pending").length;

  auditLog("ADMIN_READ", { operation: "stats", ip });

  return secureJson({
    registeredUsers: (allUsers || []).length,
    pendingWithdrawals,
    timestamp: new Date().toISOString(),
  });
};

export const config: Config = {
  path: "/api/admin",
  method: ["GET"],
};
