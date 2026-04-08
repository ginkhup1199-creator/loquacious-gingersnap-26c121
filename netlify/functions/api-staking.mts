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
import { randomUUID } from "crypto";

interface Stake {
  id: string;
  wallet: string;
  amount: number;
  apy: number;
  daysLocked: number;
  startAt: string;
  status: "active" | "completed" | "cancelled";
  completedAt?: string;
  profit?: number;
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Service not configured" }, 503);
  }

  // ── GET: return stakes for a wallet ────────────────────────────────────────
  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");
    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }
    const safeWallet = sanitizeString(wallet, 100).toLowerCase();
    const stakes = ((await store.get(`stakes-${safeWallet}`, { type: "json" })) ?? []) as Stake[];
    return secureJson(stakes, 200, true);
  }

  // ── POST: create or manage stakes ──────────────────────────────────────────
  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    const action = sanitizeString(String(body.action ?? ""), 32);

    // ── User: stake USDT ────────────────────────────────────────────────────
    if (action === "stake") {
      const wallet = sanitizeString(String(body.wallet ?? ""), 100).toLowerCase();
      if (!wallet) return secureJson({ error: "Wallet address required" }, 400);

      const amount = parseFloat(String(body.amount ?? "0"));
      if (isNaN(amount) || amount <= 0) {
        return secureJson({ error: "Invalid stake amount" }, 400);
      }

      // Read current balance
      const balance = ((await store.get(`balance-${wallet}`, { type: "json" })) ?? { usdt: 0 }) as { usdt: number };
      if (balance.usdt < amount) {
        return secureJson({ error: "Insufficient balance" }, 400);
      }

      // Read current settings for APY
      const settings = (await store.get("settings", { type: "json" })) as Record<string, number> | null;
      const apy = parseFloat(String(settings?.btcStakingApy ?? 12.5));

      // Deduct from balance
      balance.usdt = parseFloat((balance.usdt - amount).toFixed(2));
      await store.setJSON(`balance-${wallet}`, balance);

      const newStake: Stake = {
        id: randomUUID(),
        wallet,
        amount,
        apy,
        daysLocked: 30,
        startAt: new Date().toISOString(),
        status: "active",
      };

      const stakes = ((await store.get(`stakes-${wallet}`, { type: "json" })) ?? []) as Stake[];
      stakes.unshift(newStake);
      await store.setJSON(`stakes-${wallet}`, stakes);

      auditLog("STAKE_CREATED", { wallet: `${wallet.slice(0, 8)}…`, amount, apy, ip });
      return secureJson({ success: true, stake: newStake, newBalance: balance });
    }

    // ── Admin: complete a stake (pay out principal + profit) ────────────────
    if (action === "complete") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "stake-complete", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const wallet = sanitizeString(String(body.wallet ?? ""), 100).toLowerCase();
      const stakeId = sanitizeString(String(body.stakeId ?? ""), 64);
      if (!wallet) return secureJson({ error: "Wallet address required" }, 400);
      if (!stakeId) return secureJson({ error: "Stake ID required" }, 400);

      const stakes = ((await store.get(`stakes-${wallet}`, { type: "json" })) ?? []) as Stake[];
      const idx = stakes.findIndex((s) => s.id === stakeId);
      if (idx === -1) return secureJson({ error: "Stake not found" }, 404);

      const stake = stakes[idx];
      if (stake.status !== "active") {
        return secureJson({ error: "Stake is not active" }, 400);
      }

      // Calculate profit: APY pro-rated by days elapsed using startAt timestamp
      const msElapsed = Date.now() - new Date(stake.startAt).getTime();
      const daysElapsed = Math.max(1, msElapsed / (1000 * 60 * 60 * 24));
      const profit = parseFloat((stake.amount * (stake.apy / 100) * (daysElapsed / 365)).toFixed(2));
      const payout = stake.amount + profit;

      const balance = ((await store.get(`balance-${wallet}`, { type: "json" })) ?? { usdt: 0 }) as { usdt: number };
      balance.usdt = parseFloat((balance.usdt + payout).toFixed(2));
      await store.setJSON(`balance-${wallet}`, balance);

      stakes[idx].status = "completed";
      stakes[idx].completedAt = new Date().toISOString();
      stakes[idx].profit = profit;
      await store.setJSON(`stakes-${wallet}`, stakes);

      await persistAuditLog("ADMIN_WRITE", {
        operation: "stake-complete", wallet: `${wallet.slice(0, 8)}…`,
        stakeId, profit, payout, ip,
      }, store);

      return secureJson({ success: true, profit, payout, newBalance: balance });
    }

    // ── Admin: cancel a stake (refund principal only) ───────────────────────
    if (action === "cancel") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "stake-cancel", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const wallet = sanitizeString(String(body.wallet ?? ""), 100).toLowerCase();
      const stakeId = sanitizeString(String(body.stakeId ?? ""), 64);
      if (!wallet) return secureJson({ error: "Wallet address required" }, 400);
      if (!stakeId) return secureJson({ error: "Stake ID required" }, 400);

      const stakes = ((await store.get(`stakes-${wallet}`, { type: "json" })) ?? []) as Stake[];
      const idx = stakes.findIndex((s) => s.id === stakeId);
      if (idx === -1) return secureJson({ error: "Stake not found" }, 404);

      const stake = stakes[idx];
      if (stake.status !== "active") {
        return secureJson({ error: "Stake is not active" }, 400);
      }

      // Refund principal only
      const balance = ((await store.get(`balance-${wallet}`, { type: "json" })) ?? { usdt: 0 }) as { usdt: number };
      balance.usdt = parseFloat((balance.usdt + stake.amount).toFixed(2));
      await store.setJSON(`balance-${wallet}`, balance);

      stakes[idx].status = "cancelled";
      stakes[idx].completedAt = new Date().toISOString();
      await store.setJSON(`stakes-${wallet}`, stakes);

      await persistAuditLog("ADMIN_WRITE", {
        operation: "stake-cancel", wallet: `${wallet.slice(0, 8)}…`,
        stakeId, refunded: stake.amount, ip,
      }, store);

      return secureJson({ success: true, refunded: stake.amount, newBalance: balance });
    }

    return secureJson({ error: "Invalid action" }, 400);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/staking",
  method: ["GET", "POST"],
};
