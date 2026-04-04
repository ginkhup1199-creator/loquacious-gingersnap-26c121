import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import crypto from "node:crypto";

const DEMO_RATES: Record<string, number> = {
  USDT: 1, USDC: 1, ETH: 3200, BTC: 65000, BNB: 600, SOL: 145,
  XRP: 0.58, ADA: 0.45, AVAX: 35, DOGE: 0.15,
};

const VALID_COINS = Object.keys(DEMO_RATES);
const VALID_TRADE_TYPES = ["spot", "binary", "ai-arbitrage", "swap", "binary-result"];

// LLM injection patterns
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior)\s+(instructions?|prompts?)/i,
  /system\s*:\s*(ignore|override|forget)/i,
  /<\|system\|>|<\|user\|>|\[INST\]/i,
  /reveal\s+(all|your|the)\s+(secret|hidden|api|admin)\s+(key|token|password)/i,
];

function isSafeInput(input: string): boolean {
  return !INJECTION_PATTERNS.some((p) => p.test(input));
}

function auditLog(action: string, details: Record<string, unknown>): void {
  console.log(`[AUDIT] ${JSON.stringify({ timestamp: new Date().toISOString(), action, ...details })}`);
}

function getClientIp(req: Request, context: Context): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-nf-client-connection-ip") ||
    context.ip ||
    "unknown";
}

function sanitize(input: unknown, maxLen = 200): string {
  if (typeof input !== "string") return "";
  return input.replace(/<[^>]*>/g, "").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim().slice(0, maxLen);
}

// Rate limiter
const rateLimitMap = new Map<string, { count: number; windowStart: number }>();
function isRateLimited(ip: string): boolean {
  const now = Date.now();
  for (const [k, v] of rateLimitMap.entries()) {
    if (now - v.windowStart > 60000) rateLimitMap.delete(k);
  }
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > 60000) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return false;
  }
  entry.count += 1;
  return entry.count > 30;
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(req, context);

  if (isRateLimited(ip)) {
    auditLog("RATE_LIMIT_EXCEEDED", { ip, path: "/api/trades" });
    return Response.json({ error: "Too many requests" }, { status: 429 });
  }

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");
    if (!wallet) {
      return Response.json({ error: "Wallet address required" }, { status: 400 });
    }
    const walletKey = sanitize(wallet, 100).toLowerCase();
    if (!walletKey) {
      return Response.json({ error: "Invalid wallet address" }, { status: 400 });
    }
    const trades = (await store.get(`trades-${walletKey}`, { type: "json" })) as unknown[] || [];
    return Response.json(trades);
  }

  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }

    const rawWallet = body.wallet as string;
    if (!rawWallet || typeof rawWallet !== "string") {
      return Response.json({ error: "Wallet address required" }, { status: 400 });
    }

    const walletKey = sanitize(rawWallet, 100).toLowerCase();
    if (!walletKey) {
      return Response.json({ error: "Invalid wallet address" }, { status: 400 });
    }

    const type = sanitize(body.type as string, 30);

    // Validate trade type
    if (type && !VALID_TRADE_TYPES.includes(type)) {
      return Response.json({ error: "Invalid trade type" }, { status: 400 });
    }

    // Scan string fields for injection
    for (const field of ["type", "fromCoin", "toCoin", "levelName", "direction"]) {
      const val = body[field];
      if (typeof val === "string" && !isSafeInput(val)) {
        auditLog("INJECTION_BLOCKED", { ip, field, path: "/api/trades" });
        return Response.json({ error: "Invalid input detected" }, { status: 400 });
      }
    }

    // Handle binary trade result (called after timer expires on client)
    if (type === "binary-result") {
      const profit = parseFloat(body.profit as string);
      const tradeId = body.tradeId;

      if (isNaN(profit)) {
        return Response.json({ error: "Invalid profit value" }, { status: 400 });
      }

      const balance = ((await store.get(`balance-${walletKey}`, { type: "json" })) || { usdt: 0 }) as { usdt: number };
      balance.usdt = Math.max(0, balance.usdt + profit);
      await store.setJSON(`balance-${walletKey}`, balance);

      const trades = ((await store.get(`trades-${walletKey}`, { type: "json" })) as Array<Record<string, unknown>>) || [];
      const tradeIdx = trades.findIndex((t) => t.id === tradeId);
      if (tradeIdx !== -1) {
        trades[tradeIdx].status = profit >= 0 ? "won" : "lost";
        trades[tradeIdx].profit = profit;
        trades[tradeIdx].completedAt = new Date().toISOString();
        await store.setJSON(`trades-${walletKey}`, trades);
      }

      auditLog("TRADE_COMPLETED", { ip, wallet: walletKey, tradeId, profit });
      return Response.json({ success: true, newBalance: balance });
    }

    // Record a new trade
    const trades = ((await store.get(`trades-${walletKey}`, { type: "json" })) as Array<Record<string, unknown>>) || [];
    const newTrade: Record<string, unknown> = {
      id: crypto.randomUUID(),
      type,
      status: "active",
      createdAt: new Date().toISOString(),
      completedAt: null,
    };

    // Copy allowed fields with sanitization
    const allowedFields = ["direction", "levelId", "levelName", "capital", "tradingTime",
      "profitPercent", "dailyProfit", "duration"];
    for (const field of allowedFields) {
      if (body[field] !== undefined) {
        newTrade[field] = typeof body[field] === "string"
          ? sanitize(body[field] as string, 100)
          : body[field];
      }
    }

    // Validate numeric fields
    if (body.capital !== undefined) {
      const capital = parseFloat(body.capital as string);
      if (isNaN(capital) || capital < 0) {
        return Response.json({ error: "Invalid capital value" }, { status: 400 });
      }
      newTrade.capital = capital;
    }

    // Swap: validate coins and calculate output
    if (type === "swap") {
      const fromCoin = sanitize(body.fromCoin as string, 10).toUpperCase();
      const toCoin = sanitize(body.toCoin as string, 10).toUpperCase();
      const amount = parseFloat(body.amount as string);

      if (!VALID_COINS.includes(fromCoin) || !VALID_COINS.includes(toCoin)) {
        return Response.json({ error: "Invalid coin for swap" }, { status: 400 });
      }

      if (isNaN(amount) || amount <= 0) {
        return Response.json({ error: "Invalid swap amount" }, { status: 400 });
      }

      const fromRate = DEMO_RATES[fromCoin] || 1;
      const toRate = DEMO_RATES[toCoin] || 1;
      const feeMultiplier = 0.995;
      newTrade.fromCoin = fromCoin;
      newTrade.toCoin = toCoin;
      newTrade.amount = amount;
      newTrade.estimatedOut = parseFloat(((amount * fromRate) / toRate * feeMultiplier).toFixed(6));
      newTrade.fee = parseFloat((amount * 0.005).toFixed(6));
    }

    trades.unshift(newTrade);
    if (trades.length > 100) trades.length = 100;
    await store.setJSON(`trades-${walletKey}`, trades);

    auditLog("TRADE_CREATED", { ip, wallet: walletKey, type, tradeId: newTrade.id });
    return Response.json(newTrade);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/trades",
  method: ["GET", "POST"],
};
