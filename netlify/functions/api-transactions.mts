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
import { parseJsonObject } from "../lib/validation.js";

const ALLOWED_TYPES = ["deposit", "withdrawal", "trade", "swap", "earn", "ai-bot"] as const;
const ALLOWED_STATUSES = ["Pending", "Completed", "Failed", "Cancelled"] as const;

export default async (req: Request, context: Context) => {
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  const store = getStore({ name: "app-data", consistency: "strong" });
  const url = new URL(req.url);

  // ─── GET /api/transactions ────────────────────────────────────────────────
  // Returns transaction history for a wallet address
  if (req.method === "GET") {
    const wallet = url.searchParams.get("wallet");
    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }

    const safeWallet = sanitizeString(wallet, 100).toLowerCase();
    if (!safeWallet) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }

    const txKey = `transactions-${safeWallet}`;
    const transactions = await store.get(txKey, { type: "json" });
    return secureJson(transactions || [], 200, true);
  }

  // ─── POST /api/transactions ───────────────────────────────────────────────
  // Records a new transaction (admin-only for manual recording)
  if (req.method === "POST") {
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "record-transaction", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    let body: Record<string, unknown>;
    try {
      body = await parseJsonObject(req);
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    const wallet = sanitizeString(body.wallet as string, 100).toLowerCase();
    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }

    const type = body.type as string;
    if (!ALLOWED_TYPES.includes(type as typeof ALLOWED_TYPES[number])) {
      return secureJson({ error: "Invalid transaction type" }, 400);
    }

    const status = (body.status as string) || "Completed";
    if (!ALLOWED_STATUSES.includes(status as typeof ALLOWED_STATUSES[number])) {
      return secureJson({ error: "Invalid status" }, 400);
    }

    const amount = parseFloat(body.amount as string);
    if (isNaN(amount)) {
      return secureJson({ error: "Invalid amount" }, 400);
    }

    const coin = sanitizeString(body.coin as string, 10) || "USDT";
    const notes = sanitizeString(body.notes as string, 200);

    const transaction = {
      id: crypto.randomUUID(),
      wallet,
      type,
      coin,
      amount,
      status,
      notes,
      createdAt: new Date().toISOString(),
    };

    const txKey = `transactions-${wallet}`;
    const existing = ((await store.get(txKey, { type: "json" })) || []) as unknown[];
    existing.unshift(transaction);
    // Keep only latest 100 transactions
    if (existing.length > 100) existing.splice(100);
    await store.setJSON(txKey, existing);

    await persistAuditLog("ADMIN_WRITE", { operation: "record-transaction", wallet: `${wallet.slice(0, 8)}…`, type, ip }, store);

    return secureJson(transaction, 201);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/v2/transactions",
  method: ["GET", "POST"],
};
