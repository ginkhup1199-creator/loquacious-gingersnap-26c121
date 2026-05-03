/**
 * GET /api/v2/master?action=<action>
 *
 * Unified read-only aggregation endpoint for the admin dashboard.
 * Requires a valid master or sub-admin session (X-Session-Token).
 * Sub-admins are restricted to actions matching their permissions.
 *
 * Supported actions:
 *   stats        – platform-wide counters
 *   users        – all registered users
 *   balances     – all user balances (multi-coin)
 *   trades       – all trades across all wallets
 *   withdrawals  – all withdrawal requests
 *   kyc          – all KYC submissions
 *   audit-logs   – last 500 audit events
 *   transactions – all transactions across all wallets
 */

import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAnyAdminSession,
  hasPermission,
  secureJson,
  auditLog,
  getClientIp,
} from "../lib/security.js";

// ---------------------------------------------------------------------------
// Permission map: which sub-admin permission is required per action.
// Master sessions bypass all permission checks.
// ---------------------------------------------------------------------------
const ACTION_PERMISSIONS: Record<string, string | null> = {
  stats: null,          // any authenticated admin
  users: "users",
  balances: "users",
  trades: "trades",
  withdrawals: "withdrawals",
  kyc: "kyc",
  "audit-logs": "settings",
  transactions: "users",
};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Service not configured" }, 503);
  }

  if (req.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  // ── Auth ──────────────────────────────────────────────────────────────────
  const sessionResult = await validateAnyAdminSession(req, store);
  if (!sessionResult.valid) {
    auditLog("AUTH_FAILURE", { operation: "master-read", reason: sessionResult.reason, ip });
    return secureJson({ error: "Unauthorized" }, 401);
  }

  // ── Action routing ────────────────────────────────────────────────────────
  const url = new URL(req.url);
  const action = (url.searchParams.get("action") ?? "").trim().toLowerCase();

  if (!action || !(action in ACTION_PERMISSIONS)) {
    return secureJson(
      { error: "Invalid action. Valid actions: stats, users, balances, trades, withdrawals, kyc, audit-logs, transactions" },
      400
    );
  }

  // Permission check for sub-admins
  const requiredPerm = ACTION_PERMISSIONS[action];
  if (requiredPerm !== null && !hasPermission(sessionResult, requiredPerm)) {
    auditLog("AUTH_FAILURE", { operation: `master-${action}`, reason: "insufficient permissions", ip });
    return secureJson({ error: "Permission denied" }, 403);
  }

  // ── Data fetching ─────────────────────────────────────────────────────────

  if (action === "stats") {
    const [allUsers, withdrawals, kycPending, allTrades] = await Promise.all([
      store.get("all-users", { type: "json" }) as Promise<any[] | null>,
      store.get("withdrawals", { type: "json" }) as Promise<any[] | null>,
      store.get("kyc-pending", { type: "json" }) as Promise<string[] | null>,
      store.get("all-trades-index", { type: "json" }) as Promise<any[] | null>,
    ]);

    const users = allUsers ?? [];
    const wds = withdrawals ?? [];
    const kyc = kycPending ?? [];

    // Aggregate balances for total wallet USDT and open trade capital
    let totalWalletBalanceUsdt = 0;
    let totalOpenTradeCapitalUsdt = 0;
    let activeTrades = 0;
    let totalTrades = 0;

    // Fetch balances for all known users
    const balanceResults = await Promise.all(
      users.map((u: any) =>
        u?.wallet
          ? store.get(`balance-${String(u.wallet).toLowerCase()}`, { type: "json" })
          : Promise.resolve(null)
      )
    );
    for (const bal of balanceResults) {
      if (bal && typeof (bal as any).usdt === "number") {
        totalWalletBalanceUsdt += (bal as any).usdt;
      }
    }

    // Fetch trades for all known users
    const tradeResults = await Promise.all(
      users.map((u: any) =>
        u?.wallet
          ? store.get(`trades-${String(u.wallet).toLowerCase()}`, { type: "json" })
          : Promise.resolve(null)
      )
    );
    for (const trades of tradeResults) {
      if (Array.isArray(trades)) {
        totalTrades += trades.length;
        for (const t of trades) {
          if (t?.status === "active") {
            activeTrades++;
            totalOpenTradeCapitalUsdt += parseFloat(String(t.capital ?? 0)) || 0;
          }
        }
      }
    }

    return secureJson({
      registeredUsers: users.length,
      pendingKyc: kyc.length,
      pendingWithdrawals: wds.filter((w: any) => w?.status === "Pending").length,
      totalTrades,
      activeTrades,
      totalWalletBalanceUsdt: parseFloat(totalWalletBalanceUsdt.toFixed(2)),
      totalOpenTradeCapitalUsdt: parseFloat(totalOpenTradeCapitalUsdt.toFixed(2)),
    });
  }

  if (action === "users") {
    const allUsers = ((await store.get("all-users", { type: "json" })) ?? []) as any[];
    return secureJson(allUsers);
  }

  if (action === "balances") {
    const allUsers = ((await store.get("all-users", { type: "json" })) ?? []) as any[];
    const COINS = ["usdt", "btc", "eth", "sol", "bnb", "xrp", "ada", "avax", "doge", "usdc"] as const;

    const balances = await Promise.all(
      allUsers.map(async (u: any) => {
        if (!u?.wallet) return null;
        const wallet = String(u.wallet).toLowerCase();
        const bal = ((await store.get(`balance-${wallet}`, { type: "json" })) ?? {}) as Record<string, number>;
        const entry: Record<string, unknown> = { wallet };
        for (const coin of COINS) {
          entry[coin] = typeof bal[coin] === "number" ? bal[coin] : 0;
        }
        return entry;
      })
    );

    return secureJson(balances.filter(Boolean));
  }

  if (action === "trades") {
    const allUsers = ((await store.get("all-users", { type: "json" })) ?? []) as any[];
    const allTrades: any[] = [];

    const tradeResults = await Promise.all(
      allUsers.map((u: any) =>
        u?.wallet
          ? store.get(`trades-${String(u.wallet).toLowerCase()}`, { type: "json" })
          : Promise.resolve(null)
      )
    );

    for (let i = 0; i < allUsers.length; i++) {
      const wallet = allUsers[i]?.wallet;
      const trades = tradeResults[i];
      if (Array.isArray(trades) && wallet) {
        for (const t of trades) {
          allTrades.push({ ...t, wallet: String(wallet).toLowerCase() });
        }
      }
    }

    // Sort newest first
    allTrades.sort((a, b) => new Date(b.createdAt ?? 0).getTime() - new Date(a.createdAt ?? 0).getTime());
    return secureJson(allTrades);
  }

  if (action === "withdrawals") {
    const withdrawals = ((await store.get("withdrawals", { type: "json" })) ?? []) as any[];
    return secureJson(withdrawals);
  }

  if (action === "kyc") {
    const pendingList = ((await store.get("kyc-pending", { type: "json" })) ?? []) as string[];
    // Also fetch all users to include approved/rejected KYC records
    const allUsers = ((await store.get("all-users", { type: "json" })) ?? []) as any[];
    const allWallets = Array.from(
      new Set([...pendingList, ...allUsers.map((u: any) => String(u?.wallet ?? "").toLowerCase()).filter(Boolean)])
    );

    const kycRecords = await Promise.all(
      allWallets.map((w) => store.get(`kyc-${w}`, { type: "json" }))
    );

    const results = kycRecords
      .map((rec, i) => (rec ? { ...rec as object, wallet: allWallets[i] } : null))
      .filter(Boolean);

    return secureJson(results);
  }

  if (action === "audit-logs") {
    const logs = ((await store.get("audit-log", { type: "json" })) ?? []) as any[];
    return secureJson(logs);
  }

  if (action === "transactions") {
    const allUsers = ((await store.get("all-users", { type: "json" })) ?? []) as any[];
    const allTx: any[] = [];

    const txResults = await Promise.all(
      allUsers.map((u: any) =>
        u?.wallet
          ? store.get(`transactions-${String(u.wallet).toLowerCase()}`, { type: "json" })
          : Promise.resolve(null)
      )
    );

    for (let i = 0; i < allUsers.length; i++) {
      const wallet = allUsers[i]?.wallet;
      const txs = txResults[i];
      if (Array.isArray(txs) && wallet) {
        for (const tx of txs) {
          allTx.push({ ...tx, wallet: String(wallet).toLowerCase() });
        }
      }
    }

    // Sort newest first
    allTx.sort((a, b) => new Date(b.createdAt ?? 0).getTime() - new Date(a.createdAt ?? 0).getTime());
    return secureJson(allTx);
  }

  // Should never reach here given the action validation above
  return secureJson({ error: "Unknown action" }, 400);
};

export const config: Config = {
  path: "/api/v2/master",
  method: ["GET"],
};
