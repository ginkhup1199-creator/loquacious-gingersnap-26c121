import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  validateAnyAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  persistAuditLog,
  getClientIp,
} from "../lib/security.js";

/** A single staking position owned by a wallet. */
export interface StakePosition {
  id: number;
  wallet: string;
  coin: string;
  amount: number;
  apyPercent: number;
  startedAt: string;
  /** ISO date-time set when the position is closed. */
  completedAt?: string;
  profit?: number;
  status: "active" | "completed" | "cancelled";
}

const SUPPORTED_COINS = ["BTC", "ETH", "USDT", "BNB", "SOL"] as const;
const MAX_POSITIONS_PER_WALLET = 20;

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  // ── GET /api/staking ──────────────────────────────────────────────────────
  if (req.method === "GET") {
    const url = new URL(req.url);
    const walletParam = url.searchParams.get("wallet");
    const listAll = url.searchParams.get("list");

    // Admin: list ALL staking positions across all wallets
    if (listAll === "true") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "list-all-stakes", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }
      const all = ((await store.get("staking-all", { type: "json" })) || []) as StakePosition[];
      return secureJson(all, 200, true);
    }

    // Per-wallet: return this user's staking positions (no auth required for own wallet)
    if (!walletParam) {
      return secureJson({ error: "Wallet address required" }, 400);
    }
    const safeWallet = sanitizeString(walletParam, 100).toLowerCase();
    if (!safeWallet) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }
    const positions = ((await store.get(`staking-${safeWallet}`, { type: "json" })) || []) as StakePosition[];
    return secureJson(positions, 200, true);
  }

  // ── POST /api/staking ─────────────────────────────────────────────────────
  if (req.method === "POST") {
    let body: any;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }
    const { action } = body;

    // ── User action: stake ────────────────────────────────────────────────────
    if (action === "stake") {
      const { wallet, coin, amount } = body;
      if (!wallet) return secureJson({ error: "Wallet address required" }, 400);

      const safeWallet = sanitizeString(String(wallet), 100).toLowerCase();
      if (!safeWallet) return secureJson({ error: "Invalid wallet address" }, 400);

      const safeCoin = sanitizeString(String(coin ?? "BTC"), 10).toUpperCase();
      if (!SUPPORTED_COINS.includes(safeCoin as any)) {
        return secureJson({ error: `Unsupported coin. Supported: ${SUPPORTED_COINS.join(", ")}` }, 400);
      }

      const stakeAmount = parseFloat(String(amount ?? 0));
      if (!stakeAmount || stakeAmount <= 0) {
        return secureJson({ error: "Stake amount must be greater than zero" }, 400);
      }

      // Fetch current settings for APY
      const settings = ((await store.get("settings", { type: "json" })) || { btcStakingApy: 12.5 }) as Record<string, number>;
      const apyPercent = settings.btcStakingApy ?? 12.5;

      // Deduct from balance (USDT only for now — all coins tracked as USDT-equivalent value)
      const balance = ((await store.get(`balance-${safeWallet}`, { type: "json" })) || { usdt: 0 }) as { usdt: number };
      if (balance.usdt < stakeAmount) {
        return secureJson({ error: "Insufficient USDT balance" }, 400);
      }

      // Enforce per-wallet position cap
      const existing = ((await store.get(`staking-${safeWallet}`, { type: "json" })) || []) as StakePosition[];
      if (existing.filter((p) => p.status === "active").length >= MAX_POSITIONS_PER_WALLET) {
        return secureJson({ error: `Maximum ${MAX_POSITIONS_PER_WALLET} active positions allowed` }, 400);
      }

      balance.usdt = parseFloat((balance.usdt - stakeAmount).toFixed(2));
      await store.setJSON(`balance-${safeWallet}`, balance);

      const position: StakePosition = {
        id: Date.now(),
        wallet: safeWallet,
        coin: safeCoin,
        amount: stakeAmount,
        apyPercent,
        startedAt: new Date().toISOString(),
        status: "active",
      };

      existing.unshift(position);
      if (existing.length > MAX_POSITIONS_PER_WALLET * 2) existing.length = MAX_POSITIONS_PER_WALLET * 2;
      await store.setJSON(`staking-${safeWallet}`, existing);

      // Update global all-stakes index
      const allStakes = ((await store.get("staking-all", { type: "json" })) || []) as StakePosition[];
      allStakes.unshift(position);
      if (allStakes.length > 1000) allStakes.length = 1000;
      await store.setJSON("staking-all", allStakes);

      await persistAuditLog("USER_ACTION", {
        operation: "stake",
        wallet: `${safeWallet.slice(0, 8)}…`,
        coin: safeCoin,
        amount: stakeAmount,
        apyPercent,
        ip,
      }, store);

      return secureJson({ success: true, position, newBalance: balance });
    }

    // ── User action: unstake ──────────────────────────────────────────────────
    if (action === "unstake") {
      const { wallet, stakeId } = body;
      if (!wallet) return secureJson({ error: "Wallet address required" }, 400);

      const safeWallet = sanitizeString(String(wallet), 100).toLowerCase();
      if (!safeWallet) return secureJson({ error: "Invalid wallet address" }, 400);

      const id = Number(stakeId);
      const positions = ((await store.get(`staking-${safeWallet}`, { type: "json" })) || []) as StakePosition[];
      const idx = positions.findIndex((p) => p.id === id);

      if (idx === -1) return secureJson({ error: "Stake position not found" }, 404);
      if (positions[idx].status !== "active") {
        return secureJson({ error: "Position is not active" }, 400);
      }

      // Calculate prorated profit based on elapsed time (APY / 365 per day)
      const elapsedMs = Date.now() - positions[idx].id;
      const elapsedDays = elapsedMs / (1000 * 60 * 60 * 24);
      const apy = positions[idx].apyPercent / 100;
      const profit = parseFloat((positions[idx].amount * apy * (elapsedDays / 365)).toFixed(2));
      const returnAmount = parseFloat((positions[idx].amount + profit).toFixed(2));

      positions[idx].status = "completed";
      positions[idx].completedAt = new Date().toISOString();
      positions[idx].profit = profit;
      await store.setJSON(`staking-${safeWallet}`, positions);

      // Credit balance
      const balance = ((await store.get(`balance-${safeWallet}`, { type: "json" })) || { usdt: 0 }) as { usdt: number };
      balance.usdt = parseFloat((balance.usdt + returnAmount).toFixed(2));
      await store.setJSON(`balance-${safeWallet}`, balance);

      // Sync global index
      const allStakes = ((await store.get("staking-all", { type: "json" })) || []) as StakePosition[];
      const globalIdx = allStakes.findIndex((p) => p.id === id);
      if (globalIdx !== -1) {
        allStakes[globalIdx] = positions[idx];
        await store.setJSON("staking-all", allStakes);
      }

      await persistAuditLog("USER_ACTION", {
        operation: "unstake",
        wallet: `${safeWallet.slice(0, 8)}…`,
        stakeId: id,
        profit,
        returnAmount,
        ip,
      }, store);

      return secureJson({ success: true, profit, returnAmount, newBalance: balance });
    }

    // ── Admin action: complete (force-complete with profit) ───────────────────
    if (action === "admin-complete") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "admin-complete-stake", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const { wallet, stakeId, profitOverride } = body;
      if (!wallet) return secureJson({ error: "Wallet address required" }, 400);

      const safeWallet = sanitizeString(String(wallet), 100).toLowerCase();
      const id = Number(stakeId);
      const positions = ((await store.get(`staking-${safeWallet}`, { type: "json" })) || []) as StakePosition[];
      const idx = positions.findIndex((p) => p.id === id);

      if (idx === -1) return secureJson({ error: "Stake position not found" }, 404);
      if (positions[idx].status !== "active") {
        return secureJson({ error: "Position is not active" }, 400);
      }

      const profit = profitOverride !== undefined
        ? parseFloat(String(profitOverride))
        : (() => {
            const elapsedMs = Date.now() - positions[idx].id;
            const elapsedDays = elapsedMs / (1000 * 60 * 60 * 24);
            const apy = positions[idx].apyPercent / 100;
            return parseFloat((positions[idx].amount * apy * (elapsedDays / 365)).toFixed(2));
          })();

      if (isNaN(profit)) return secureJson({ error: "Invalid profit value" }, 400);

      const returnAmount = parseFloat((positions[idx].amount + profit).toFixed(2));
      positions[idx].status = "completed";
      positions[idx].completedAt = new Date().toISOString();
      positions[idx].profit = profit;
      await store.setJSON(`staking-${safeWallet}`, positions);

      const balance = ((await store.get(`balance-${safeWallet}`, { type: "json" })) || { usdt: 0 }) as { usdt: number };
      balance.usdt = parseFloat((balance.usdt + returnAmount).toFixed(2));
      await store.setJSON(`balance-${safeWallet}`, balance);

      // Sync global index
      const allStakes = ((await store.get("staking-all", { type: "json" })) || []) as StakePosition[];
      const globalIdx = allStakes.findIndex((p) => p.id === id);
      if (globalIdx !== -1) {
        allStakes[globalIdx] = positions[idx];
        await store.setJSON("staking-all", allStakes);
      }

      await persistAuditLog("ADMIN_WRITE", {
        operation: "admin-complete-stake",
        wallet: `${safeWallet.slice(0, 8)}…`,
        stakeId: id,
        profit,
        returnAmount,
        ip,
      }, store);

      return secureJson({ success: true, profit, returnAmount, newBalance: balance });
    }

    // ── Admin action: cancel (return principal, no profit) ────────────────────
    if (action === "admin-cancel") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "admin-cancel-stake", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const { wallet, stakeId } = body;
      if (!wallet) return secureJson({ error: "Wallet address required" }, 400);

      const safeWallet = sanitizeString(String(wallet), 100).toLowerCase();
      const id = Number(stakeId);
      const positions = ((await store.get(`staking-${safeWallet}`, { type: "json" })) || []) as StakePosition[];
      const idx = positions.findIndex((p) => p.id === id);

      if (idx === -1) return secureJson({ error: "Stake position not found" }, 404);
      if (positions[idx].status !== "active") {
        return secureJson({ error: "Position is not active" }, 400);
      }

      const refund = positions[idx].amount;
      positions[idx].status = "cancelled";
      positions[idx].completedAt = new Date().toISOString();
      positions[idx].profit = 0;
      await store.setJSON(`staking-${safeWallet}`, positions);

      const balance = ((await store.get(`balance-${safeWallet}`, { type: "json" })) || { usdt: 0 }) as { usdt: number };
      balance.usdt = parseFloat((balance.usdt + refund).toFixed(2));
      await store.setJSON(`balance-${safeWallet}`, balance);

      // Sync global index
      const allStakes = ((await store.get("staking-all", { type: "json" })) || []) as StakePosition[];
      const globalIdx = allStakes.findIndex((p) => p.id === id);
      if (globalIdx !== -1) {
        allStakes[globalIdx] = positions[idx];
        await store.setJSON("staking-all", allStakes);
      }

      await persistAuditLog("ADMIN_WRITE", {
        operation: "admin-cancel-stake",
        wallet: `${safeWallet.slice(0, 8)}…`,
        stakeId: id,
        refund,
        ip,
      }, store);

      return secureJson({ success: true, refund, newBalance: balance });
    }

    return secureJson({ error: "Invalid action" }, 400);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/staking",
  method: ["GET", "POST"],
};
