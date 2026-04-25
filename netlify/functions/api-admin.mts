import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  auditLog,
  getClientIp,
} from "../lib/security.js";

/**
 * GET /api/v2/admin?action=stats
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

  const users = ((allUsers || []) as Array<{ wallet?: string }>)
    .filter((u) => u && typeof u.wallet === "string");
  const uniqueWallets = Array.from(new Set(users.map((u) => (u.wallet || "").toLowerCase()).filter(Boolean)));

  let activeTrades = 0;
  let totalTrades = 0;
  let totalWalletBalanceUsdt = 0;
  let totalOpenTradeCapitalUsdt = 0;

  await Promise.all(uniqueWallets.map(async (wallet) => {
    const [balance, trades] = await Promise.all([
      store.get(`balance-${wallet}`, { type: "json" }) as Promise<{ usdt?: number } | null>,
      store.get(`trades-${wallet}`, { type: "json" }) as Promise<Array<{ status?: string; capital?: number | string }> | null>,
    ]);

    totalWalletBalanceUsdt += Number(balance?.usdt ?? 0);

    const walletTrades = trades || [];
    totalTrades += walletTrades.length;
    for (const trade of walletTrades) {
      if (trade?.status === "active") {
        activeTrades += 1;
        totalOpenTradeCapitalUsdt += Number(trade.capital ?? 0) || 0;
      }
    }
  }));

  const pendingWithdrawals = ((withdrawals || []) as Array<{ status: string }>)
    .filter((w) => w.status === "Pending").length;

  auditLog("ADMIN_READ", { operation: "stats", ip });

  return secureJson({
    registeredUsers: users.length,
    pendingWithdrawals,
    totalTrades,
    activeTrades,
    totalWalletBalanceUsdt: Number(totalWalletBalanceUsdt.toFixed(2)),
    totalOpenTradeCapitalUsdt: Number(totalOpenTradeCapitalUsdt.toFixed(2)),
    timestamp: new Date().toISOString(),
  });
};

export const config: Config = {
  path: "/api/v2/admin",
  method: ["GET"],
};
