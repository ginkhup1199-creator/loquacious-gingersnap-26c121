import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import crypto from "node:crypto";

interface Transaction {
  id: string;
  type: "deposit" | "withdrawal" | "trade" | "swap" | "adjustment";
  status: "pending" | "completed" | "failed" | "cancelled";
  wallet: string;
  coin: string;
  amount: number;
  fee: number;
  txHash?: string;
  fromCoin?: string;
  toCoin?: string;
  toAmount?: number;
  reference?: string;
  createdAt: string;
  updatedAt: string;
  adminNote?: string;
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

function validateAdminToken(req: Request): boolean {
  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) return false;
  const provided = req.headers.get("X-Admin-Token");
  if (!provided) return false;
  try {
    const a = Buffer.from(provided);
    const b = Buffer.from(adminToken);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function sanitize(input: unknown, maxLen = 200): string {
  if (typeof input !== "string") return "";
  return input.replace(/<[^>]*>/g, "").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim().slice(0, maxLen);
}

const VALID_COINS = ["USDT", "USDC", "BTC", "ETH", "BNB", "SOL", "XRP", "ADA", "AVAX", "DOGE"];

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
  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) {
    return Response.json({ error: "Admin token not configured" }, { status: 503 });
  }

  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(req, context);
  const url = new URL(req.url);

  if (isRateLimited(ip)) {
    auditLog("RATE_LIMIT_EXCEEDED", { ip, path: "/api/transactions" });
    return Response.json({ error: "Too many requests" }, { status: 429 });
  }

  // ─── GET /api/transactions ────────────────────────────────────────────────
  if (req.method === "GET") {
    const wallet = url.searchParams.get("wallet");
    const limitParam = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 100);

    if (!wallet) {
      return Response.json({ error: "Wallet address required" }, { status: 400 });
    }

    const walletKey = sanitize(wallet, 100).toLowerCase();
    if (!walletKey) {
      return Response.json({ error: "Invalid wallet address" }, { status: 400 });
    }

    const transactions = ((await store.get(`transactions-${walletKey}`, { type: "json" })) as Transaction[]) || [];
    return Response.json(transactions.slice(0, limitParam));
  }

  // ─── POST /api/transactions ───────────────────────────────────────────────
  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }

    const { action } = body;

    // ── Record a trade/swap transaction (called from api-trades) ──────────
    if (action === "record") {
      const wallet = sanitize(body.wallet as string, 100).toLowerCase();
      const type = body.type as Transaction["type"];
      const coin = sanitize(body.coin as string, 10).toUpperCase();
      const amount = parseFloat(body.amount as string);

      if (!wallet || !type || !coin || isNaN(amount) || amount < 0) {
        return Response.json({ error: "Invalid transaction parameters" }, { status: 400 });
      }

      if (!VALID_COINS.includes(coin)) {
        return Response.json({ error: "Unsupported coin" }, { status: 400 });
      }

      const validTypes = ["deposit", "withdrawal", "trade", "swap", "adjustment"];
      if (!validTypes.includes(type)) {
        return Response.json({ error: "Invalid transaction type" }, { status: 400 });
      }

      const now = new Date().toISOString();
      const tx: Transaction = {
        id: crypto.randomUUID(),
        type,
        status: "completed",
        wallet,
        coin,
        amount,
        fee: parseFloat(body.fee as string) || 0,
        ...(body.txHash && { txHash: sanitize(body.txHash as string, 100) }),
        ...(body.fromCoin && { fromCoin: sanitize(body.fromCoin as string, 10).toUpperCase() }),
        ...(body.toCoin && { toCoin: sanitize(body.toCoin as string, 10).toUpperCase() }),
        ...(body.toAmount !== undefined && { toAmount: parseFloat(body.toAmount as string) }),
        ...(body.reference && { reference: sanitize(body.reference as string, 100) }),
        createdAt: now,
        updatedAt: now,
      };

      const transactions = ((await store.get(`transactions-${wallet}`, { type: "json" })) as Transaction[]) || [];
      transactions.unshift(tx);
      if (transactions.length > 200) transactions.length = 200;
      await store.setJSON(`transactions-${wallet}`, transactions);

      auditLog("TRANSACTION_CREATED", { ip, txId: tx.id, type, wallet, coin, amount });
      return Response.json(tx);
    }

    // ── Admin: update transaction status ──────────────────────────────────
    if (action === "update-status") {
      if (!validateAdminToken(req)) {
        auditLog("UNAUTHORIZED_ACCESS", { ip, resource: "transactions/update-status" });
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }

      const wallet = sanitize(body.wallet as string, 100).toLowerCase();
      const txId = sanitize(body.txId as string, 100);
      const status = body.status as Transaction["status"];

      const validStatuses = ["pending", "completed", "failed", "cancelled"];
      if (!wallet || !txId || !validStatuses.includes(status)) {
        return Response.json({ error: "Invalid parameters" }, { status: 400 });
      }

      const transactions = ((await store.get(`transactions-${wallet}`, { type: "json" })) as Transaction[]) || [];
      const idx = transactions.findIndex((t) => t.id === txId);
      if (idx === -1) {
        return Response.json({ error: "Transaction not found" }, { status: 404 });
      }

      transactions[idx].status = status;
      transactions[idx].updatedAt = new Date().toISOString();
      if (body.adminNote) {
        transactions[idx].adminNote = sanitize(body.adminNote as string, 500);
      }

      await store.setJSON(`transactions-${wallet}`, transactions);
      auditLog("TRANSACTION_PROCESSED", { ip, txId, wallet, status });
      return Response.json(transactions[idx]);
    }

    return Response.json({ error: "Invalid action" }, { status: 400 });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/transactions",
  method: ["GET", "POST"],
};
