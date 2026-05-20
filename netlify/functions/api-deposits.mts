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

const DEPOSIT_KEY = "deposit-submissions";
const MAX_RECORDS = 500;
const ALLOWED_STATUS = ["Pending", "Approved", "Rejected"] as const;

function isValidStatus(status: string): status is (typeof ALLOWED_STATUS)[number] {
  return (ALLOWED_STATUS as readonly string[]).includes(status);
}

export default async (req: Request, context: Context) => {
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  const store = getStore({ name: "app-data", consistency: "strong" });
  const url = new URL(req.url);

  if (req.method === "GET") {
    const list = ((await store.get(DEPOSIT_KEY, { type: "json" })) || []) as Record<string, unknown>[];
    const listMode = url.searchParams.get("list") === "true";
    const wallet = sanitizeString(String(url.searchParams.get("wallet") || ""), 100).toLowerCase();

    if (listMode) {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "list-deposits", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }
      return secureJson(list, 200);
    }

    if (!wallet) return secureJson([], 200, true);
    return secureJson(list.filter((d) => String(d.wallet || "") === wallet), 200, true);
  }

  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await parseJsonObject(req);
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    const action = sanitizeString(String(body.action || "submit"), 16).toLowerCase();
    const submissions = ((await store.get(DEPOSIT_KEY, { type: "json" })) || []) as Record<string, unknown>[];

    if (action === "process") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "process-deposit", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const id = sanitizeString(String(body.id || ""), 80);
      const status = sanitizeString(String(body.status || ""), 20);
      if (!id) return secureJson({ error: "Deposit ID required" }, 400);
      if (!isValidStatus(status)) return secureJson({ error: "Invalid status" }, 400);

      const idx = submissions.findIndex((d) => String(d.id || "") === id);
      if (idx < 0) return secureJson({ error: "Deposit submission not found" }, 404);

      submissions[idx].status = status;
      submissions[idx].reviewedAt = new Date().toISOString();
      submissions[idx].reviewNote = sanitizeString(String(body.reviewNote || ""), 300);

      // Auto-credit user balance and record transaction when deposit is approved
      if (status === "Approved") {
        const depositWallet = sanitizeString(String(submissions[idx].wallet || ""), 100).toLowerCase();
        const depositAmount = parseFloat(String(submissions[idx].amount || "0"));
        const depositCoin = sanitizeString(String(submissions[idx].coin || "USDT"), 16).toUpperCase();
        const depositNetwork = sanitizeString(String(submissions[idx].network || ""), 20).toUpperCase();
        if (depositWallet && Number.isFinite(depositAmount) && depositAmount > 0) {
          const balance = ((await store.get(`balance-${depositWallet}`, { type: "json" })) || { usdt: 0 }) as { usdt: number; [key: string]: number };
          balance.usdt = Number((Number(balance.usdt ?? 0) + depositAmount).toFixed(2));
          await store.setJSON(`balance-${depositWallet}`, balance);
          submissions[idx].balanceCredited = true;
          submissions[idx].creditedAmount = depositAmount;

          // Record the approved deposit as a transaction in the user's wallet history
          const txKey = `transactions-${depositWallet}`;
          const existingTx = ((await store.get(txKey, { type: "json" })) || []) as unknown[];
          const transaction = {
            id: crypto.randomUUID(),
            wallet: depositWallet,
            type: "deposit",
            coin: depositCoin,
            network: depositNetwork,
            amount: depositAmount,
            status: "Completed",
            notes: `Deposit approved${submissions[idx].reviewNote ? " — " + String(submissions[idx].reviewNote).slice(0, 150) : ""}`,
            createdAt: new Date().toISOString(),
          };
          existingTx.unshift(transaction);
          if (existingTx.length > 100) existingTx.splice(100);
          await store.setJSON(txKey, existingTx);
        }
      }

      await store.setJSON(DEPOSIT_KEY, submissions);
      await persistAuditLog("ADMIN_WRITE", { operation: "process-deposit", status, id, ip }, store);
      return secureJson(submissions[idx], 200);
    }

    // User submit mode
    const wallet = sanitizeString(String(body.wallet || ""), 100).toLowerCase();
    const coin = sanitizeString(String(body.coin || ""), 16).toUpperCase();
    const network = sanitizeString(String(body.network || ""), 20).toUpperCase();
    const customerAddress = sanitizeString(String(body.customerAddress || ""), 200);
    const amount = parseFloat(String(body.amount || "0"));
    const receiptImage = String(body.receiptImage || "").trim();

    if (!wallet) return secureJson({ error: "Wallet required" }, 400);
    if (!coin || !network) return secureJson({ error: "Coin and chain are required" }, 400);
    if (!customerAddress) return secureJson({ error: "Customer address required" }, 400);
    if (!Number.isFinite(amount) || amount <= 0) return secureJson({ error: "Valid amount required" }, 400);
    if (!receiptImage || (!receiptImage.startsWith("data:image/") && !/^https:\/\//i.test(receiptImage))) {
      return secureJson({ error: "Deposit receipt image is required" }, 400);
    }

    const item: Record<string, unknown> = {
      id: crypto.randomUUID(),
      wallet,
      coin,
      network,
      customerAddress,
      amount,
      receiptImage: receiptImage.slice(0, 1_500_000),
      status: "Pending",
      createdAt: new Date().toISOString(),
    };

    submissions.unshift(item);
    if (submissions.length > MAX_RECORDS) submissions.length = MAX_RECORDS;
    await store.setJSON(DEPOSIT_KEY, submissions);

    return secureJson(item, 201);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/v2/deposits",
  method: ["GET", "POST"],
};
