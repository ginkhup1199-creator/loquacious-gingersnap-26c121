import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { secureJson, sanitizeString } from "../lib/security.js";
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
    const body = await req.json();
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

      // Server-side outcome using cryptographic randomness.
      // House edge: 52 out of 100 possible outcomes are losses (48% win rate).
      const win = randomInt(0, 100) < 48;
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

      return secureJson({ success: true, won: win, profit, newBalance: balance });
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
      "profitPercent", "dailyProfit", "duration", "fromCoin", "toCoin", "amount"];
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
