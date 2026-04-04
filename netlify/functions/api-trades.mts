import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";

const DEMO_RATES: Record<string, number> = {
  USDT: 1, USDC: 1, ETH: 3200, BTC: 65000, BNB: 600, SOL: 145,
  XRP: 0.58, ADA: 0.45, AVAX: 35, DOGE: 0.15,
};

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");
    if (!wallet) {
      return Response.json({ error: "Wallet address required" }, { status: 400 });
    }
    const trades = (await store.get(`trades-${wallet.toLowerCase()}`, { type: "json" })) as any[] || [];
    return Response.json(trades);
  }

  if (req.method === "POST") {
    const body = await req.json();
    const { type, wallet } = body;

    if (!wallet) {
      return Response.json({ error: "Wallet address required" }, { status: 400 });
    }

    const walletKey = wallet.toLowerCase();

    // Handle binary trade result (called after timer expires on client)
    if (type === "binary-result") {
      const { profit, tradeId } = body;
      const balance = ((await store.get(`balance-${walletKey}`, { type: "json" })) || { usdt: 0 }) as { usdt: number };
      balance.usdt = Math.max(0, (balance.usdt || 0) + parseFloat(profit));
      await store.setJSON(`balance-${walletKey}`, balance);

      // Update trade status
      const trades = ((await store.get(`trades-${walletKey}`, { type: "json" })) as any[]) || [];
      const tradeIdx = trades.findIndex((t: any) => t.id === tradeId);
      if (tradeIdx !== -1) {
        trades[tradeIdx].status = parseFloat(profit) >= 0 ? "won" : "lost";
        trades[tradeIdx].profit = parseFloat(profit);
        await store.setJSON(`trades-${walletKey}`, trades);
      }

      return Response.json({ success: true, newBalance: balance });
    }

    // Record a new trade
    const trades = ((await store.get(`trades-${walletKey}`, { type: "json" })) as any[]) || [];
    const newTrade: Record<string, any> = {
      id: Date.now(),
      type,
      status: "active",
      createdAt: new Date().toISOString(),
    };

    // Copy allowed fields
    const allowed = ["direction", "levelId", "levelName", "capital", "tradingTime",
      "profitPercent", "dailyProfit", "duration", "fromCoin", "toCoin", "amount"];
    for (const field of allowed) {
      if (body[field] !== undefined) newTrade[field] = body[field];
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
    await store.setJSON(`trades-${walletKey}`, trades);

    return Response.json(newTrade);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/trades",
  method: ["GET", "POST"],
};
