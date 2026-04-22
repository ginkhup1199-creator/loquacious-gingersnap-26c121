import { randomUUID } from "crypto";
import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  persistAuditLog,
  getClientIp,
} from "../lib/security.js";
import { loadUsdtBalance, normalizeWallet, parseJsonObject, toNumber } from "../lib/validation.js";

type StakePosition = {
  id: string;
  wallet: string;
  coin: string;
  amount: number;
  apy: number;
  startedAt: string;
  status: "active" | "unstaked" | "cancelled" | "completed";
  settledAt?: string;
  profit?: number;
};

const COIN_APY: Record<string, number> = {
  BTC: 12.5,
  ETH: 10.5,
  USDT: 8.5,
  BNB: 9.5,
  SOL: 11.0,
};

async function loadPositions(store: ReturnType<typeof getStore>, wallet: string): Promise<StakePosition[]> {
  return ((await store.get(`staking-${wallet}`, { type: "json" })) as StakePosition[]) || [];
}

async function savePositions(store: ReturnType<typeof getStore>, wallet: string, positions: StakePosition[]) {
  await store.setJSON(`staking-${wallet}`, positions);
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = normalizeWallet(url.searchParams.get("wallet"));
    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }
    const positions = await loadPositions(store, wallet);
    return secureJson({ positions: positions.filter((p) => p.status === "active") }, 200, true);
  }

  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await parseJsonObject(req);
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }

    const action = sanitizeString(String(body.action ?? ""), 40);
    const wallet = normalizeWallet(body.wallet);

    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }

    const positions = await loadPositions(store, wallet);

    if (action === "stake") {
      const coin = sanitizeString(String(body.coin ?? "USDT"), 12).toUpperCase();
      const amount = Math.max(0, toNumber(body.amount, 0));
      if (!amount) {
        return secureJson({ error: "Invalid stake amount" }, 400);
      }

      // Deduct amount from wallet balance before staking
      const balance = await loadUsdtBalance(store, wallet);
      const currentBalance = Number(balance.usdt || 0);
      if (currentBalance < amount) {
        return secureJson({ error: "Insufficient balance" }, 400);
      }
      balance.usdt = Number((currentBalance - amount).toFixed(2));
      await store.setJSON(`balance-${wallet}`, balance);

      const position: StakePosition = {
        id: randomUUID(),
        wallet,
        coin,
        amount,
        apy: COIN_APY[coin] || COIN_APY.USDT,
        startedAt: new Date().toISOString(),
        status: "active",
      };

      positions.unshift(position);
      await savePositions(store, wallet, positions);
      await persistAuditLog("USER_WRITE", { operation: "stake", wallet: `${wallet.slice(0, 8)}…`, coin, amount, ip }, store);
      return secureJson({ success: true, position });
    }

    if (action === "unstake") {
      const positionID = sanitizeString(String(body.positionID ?? ""), 100);
      const idx = positions.findIndex((p) => p.id === positionID && p.status === "active");
      if (idx === -1) {
        return secureJson({ error: "Stake position not found" }, 404);
      }

      const position = positions[idx];
      const daysElapsed = Math.max(0, (Date.now() - new Date(position.startedAt).getTime()) / (1000 * 60 * 60 * 24));
      const profit = Number(((position.amount * position.apy * daysElapsed) / 365 / 100).toFixed(2));

      positions[idx] = {
        ...position,
        status: "unstaked",
        settledAt: new Date().toISOString(),
        profit,
      };
      await savePositions(store, wallet, positions);

      // Return principal + profit to wallet balance
      const balance = await loadUsdtBalance(store, wallet);
      balance.usdt = Number((Number(balance.usdt || 0) + position.amount + profit).toFixed(2));
      await store.setJSON(`balance-${wallet}`, balance);

      await persistAuditLog("USER_WRITE", { operation: "unstake", wallet: `${wallet.slice(0, 8)}…`, positionID, profit, ip }, store);
      return secureJson({ success: true, profit, newBalance: balance.usdt });
    }

    if (action === "admin-complete" || action === "admin-cancel") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: action, reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const nextStatus: StakePosition["status"] = action === "admin-complete" ? "completed" : "cancelled";
      const updated = positions.map((position) =>
        position.status === "active"
          ? { ...position, status: nextStatus, settledAt: new Date().toISOString() }
          : position
      );
      await savePositions(store, wallet, updated);
      await persistAuditLog("ADMIN_WRITE", { operation: action, wallet: `${wallet.slice(0, 8)}…`, ip }, store);
      return secureJson({ success: true, status: nextStatus });
    }

    return secureJson({ error: "Invalid action" }, 400);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/v2/staking",
  method: ["GET", "POST"],
};
