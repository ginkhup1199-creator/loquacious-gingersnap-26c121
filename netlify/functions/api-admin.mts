import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  auditLog,
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

  const sessionResult = await validateAdminSession(req, store);
  if (!sessionResult.valid) {
    auditLog("AUTH_FAILURE", { operation: "admin-stats", reason: sessionResult.reason, ip });
    return secureJson({ error: "Unauthorized" }, 401);
  }

  const [allUsers, withdrawals] = await Promise.all([
    store.get("all-users", { type: "json" }) as Promise<unknown[]>,
    store.get("withdrawals", { type: "json" }) as Promise<unknown[]>,
  ]);

  const pendingWithdrawals = ((withdrawals || []) as Array<{ status: string }>)
    .filter((w) => w.status === "Pending").length;

  // Master account wallet address (set via ADMIN_WALLET env var by the repo owner)
  const adminWallet = process.env.ADMIN_WALLET?.trim() || null;

  // Mask the admin email: show first 2 chars + *** + @domain
  const adminEmailRaw = process.env.ADMIN_EMAIL?.toLowerCase().trim() || "";
  let adminEmailMasked = "";
  if (adminEmailRaw) {
    const atIdx = adminEmailRaw.indexOf("@");
    const local  = atIdx > 0 ? adminEmailRaw.slice(0, atIdx) : adminEmailRaw;
    const domain = atIdx > 0 ? adminEmailRaw.slice(atIdx)    : "";
    adminEmailMasked = local.slice(0, 2) + "***" + domain;
  }

  auditLog("ADMIN_READ", { operation: "stats", ip });

  return secureJson({
    registeredUsers: (allUsers || []).length,
    pendingWithdrawals,
    adminWallet,
    adminEmailMasked,
    timestamp: new Date().toISOString(),
  });
};

export const config: Config = {
  path: "/api/admin",
  method: ["GET"],
};
