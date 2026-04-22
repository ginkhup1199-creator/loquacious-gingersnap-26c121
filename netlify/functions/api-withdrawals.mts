import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  validateAnyAdminSession,
  hasPermission,
  secureJson,
  sanitizeString,
  auditLog,
  persistAuditLog,
  getClientIp,
} from "../lib/security.js";
import { loadUsdtBalance, normalizeWallet, parseJsonObject, toArray, toNumber } from "../lib/validation.js";

type WithdrawalRecord = {
  id: number;
  wallet: string;
  coin: string;
  network: string;
  address: string;
  amount: number;
  date: string;
  status: "Pending" | "Completed" | "Rejected" | string;
};

function loadWithdrawals(value: unknown): WithdrawalRecord[] {
  return toArray<WithdrawalRecord>(value);
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const url = new URL(req.url);
    const walletParam = url.searchParams.get("wallet");

    if (walletParam) {
      // Return only this user's withdrawals (no auth needed for own wallet)
      const safeWallet = normalizeWallet(walletParam);
      const all = loadWithdrawals(await store.get("withdrawals", { type: "json" }));
      const filtered = all.filter((w) => w.wallet === safeWallet);
      return secureJson(filtered, 200, true);
    }

    // No wallet param: admin view (requires session)
    const sessionResult = await validateAnyAdminSession(req, store);
    if (!sessionResult.valid || !hasPermission(sessionResult, "withdrawals")) {
      auditLog("AUTH_FAILURE", { operation: "list-withdrawals", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }
    const withdrawals = await store.get("withdrawals", { type: "json" });
    return secureJson(withdrawals || [], 200, true);
  }

  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await parseJsonObject(req);
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }
    const action = String(body.action ?? "");

    if (action === "add") {
      const reqWallet = normalizeWallet(body.wallet);
      const reqAmount = toNumber(body.amount);
      const reqCoin = sanitizeString(String(body.coin ?? ""), 20).toUpperCase();

      if (!reqWallet || !reqAmount || reqAmount <= 0) {
        return secureJson({ error: "Invalid withdrawal request" }, 400);
      }

      // Validate user has sufficient balance before allowing withdrawal
      const balance = await loadUsdtBalance(store, reqWallet);
      // All platform balances are tracked in USDT-equivalent
      const available = Number(balance.usdt ?? 0);
      if (available < reqAmount) {
        return secureJson({ error: "Insufficient balance" }, 400);
      }

      // Deduct balance immediately to prevent double-spend
      balance.usdt = Number((available - reqAmount).toFixed(2));
      await store.setJSON(`balance-${reqWallet}`, balance);

      const existing = loadWithdrawals(await store.get("withdrawals", { type: "json" }));
      const newWithdrawal: WithdrawalRecord = {
        id: Date.now(),
        wallet: reqWallet,
        coin: reqCoin,
        network: sanitizeString(String(body.network ?? ""), 20),
        address: sanitizeString(String(body.address ?? ""), 200),
        amount: reqAmount,
        date: new Date().toISOString().split("T")[0],
        status: "Pending",
      };
      existing.push(newWithdrawal);
      await store.setJSON("withdrawals", existing);
      await persistAuditLog("USER_WRITE", { operation: "withdrawal-request", wallet: `${reqWallet.slice(0, 8)}…`, coin: reqCoin, amount: reqAmount, ip }, store);
      return secureJson(newWithdrawal);
    }

    if (action === "process") {
      const sessionResult = await validateAnyAdminSession(req, store);
      if (!sessionResult.valid || !hasPermission(sessionResult, "withdrawals")) {
        auditLog("AUTH_FAILURE", { operation: "process-withdrawal", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const newStatus = sanitizeString(String(body.status ?? "Completed"), 20);
      const allowedStatuses = ["Completed", "Rejected"];
      const safeStatus = allowedStatuses.includes(newStatus) ? newStatus : "Completed";

      await persistAuditLog("ADMIN_WRITE", { operation: "process-withdrawal", withdrawalId: body.id, status: safeStatus, ip }, store);

      const existing = loadWithdrawals(await store.get("withdrawals", { type: "json" }));
      const updated = existing.map(
        (w) => w.id === Number(body.id) ? { ...w, status: safeStatus } : w
      );
      await store.setJSON("withdrawals", updated);
      return secureJson({ success: true, status: safeStatus });
    }

    return secureJson({ error: "Invalid action" }, 400);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/v2/withdrawals",
  method: ["GET", "POST"],
};
