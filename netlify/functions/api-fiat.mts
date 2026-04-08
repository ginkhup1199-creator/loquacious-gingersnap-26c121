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

interface FiatOrder {
  id: string;
  wallet: string;
  fiatAmount: number;
  fiatCurrency: string;
  cryptoCoin: string;
  paymentMethod: string;
  estimatedCrypto: number;
  creditAmount: number;
  status: "pending" | "approved" | "rejected";
  createdAt: string;
  processedAt?: string;
}

const FEE_RATE = 0.029; // 2.9%
const MAX_WALLET_ORDERS = 100;
const MAX_GLOBAL_ORDERS = 1000;

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Service not configured" }, 503);
  }

  // ── GET: return fiat orders ────────────────────────────────────────────────
  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");

    if (wallet) {
      // User: return own orders
      const safeWallet = sanitizeString(wallet, 100).toLowerCase();
      const orders = ((await store.get(`fiat-orders-${safeWallet}`, { type: "json" })) ?? []) as FiatOrder[];
      return secureJson(orders, 200, true);
    }

    // Admin: return all pending orders
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "list-fiat-orders", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }
    const allOrders = ((await store.get("fiat-orders", { type: "json" })) ?? []) as FiatOrder[];
    return secureJson(allOrders, 200);
  }

  // ── POST: actions ─────────────────────────────────────────────────────────
  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    const action = sanitizeString(String(body.action ?? ""), 32);

    // ── User: submit a fiat buy request ─────────────────────────────────────
    if (action === "request") {
      const wallet = sanitizeString(String(body.wallet ?? ""), 100).toLowerCase();
      if (!wallet) return secureJson({ error: "Wallet address required" }, 400);

      const fiatAmount = parseFloat(String(body.fiatAmount ?? "0"));
      if (isNaN(fiatAmount) || fiatAmount <= 0) {
        return secureJson({ error: "Invalid fiat amount" }, 400);
      }
      if (fiatAmount < 10 || fiatAmount > 50000) {
        return secureJson({ error: "Fiat amount must be between $10 and $50,000" }, 400);
      }

      const fiatCurrency = sanitizeString(String(body.fiatCurrency ?? "USD"), 10);
      const cryptoCoin = sanitizeString(String(body.cryptoCoin ?? "USDT"), 20);
      const paymentMethod = sanitizeString(String(body.paymentMethod ?? "card"), 50);

      const netAmount = fiatAmount * (1 - FEE_RATE);
      const estimatedCrypto = parseFloat(netAmount.toFixed(2));

      const order: FiatOrder = {
        id: randomUUID(),
        wallet,
        fiatAmount,
        fiatCurrency,
        cryptoCoin,
        paymentMethod,
        estimatedCrypto,
        creditAmount: estimatedCrypto, // default, admin can override on approval
        status: "pending",
        createdAt: new Date().toISOString(),
      };

      // Save to per-wallet list
      const walletOrders = ((await store.get(`fiat-orders-${wallet}`, { type: "json" })) ?? []) as FiatOrder[];
      walletOrders.unshift(order);
      if (walletOrders.length > MAX_WALLET_ORDERS) walletOrders.length = MAX_WALLET_ORDERS;
      await store.setJSON(`fiat-orders-${wallet}`, walletOrders);

      // Save to global list for admin view
      const allOrders = ((await store.get("fiat-orders", { type: "json" })) ?? []) as FiatOrder[];
      allOrders.unshift(order);
      if (allOrders.length > MAX_GLOBAL_ORDERS) allOrders.length = MAX_GLOBAL_ORDERS;
      await store.setJSON("fiat-orders", allOrders);

      auditLog("FIAT_ORDER_CREATED", { wallet: `${wallet.slice(0, 8)}…`, fiatAmount, fiatCurrency, cryptoCoin, ip });
      return secureJson({ success: true, order });
    }

    // ── Admin: approve a fiat order and credit the wallet ───────────────────
    if (action === "approve") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "fiat-approve", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const orderId = sanitizeString(String(body.orderId ?? ""), 64);
      const wallet = sanitizeString(String(body.wallet ?? ""), 100).toLowerCase();
      if (!orderId) return secureJson({ error: "Order ID required" }, 400);
      if (!wallet) return secureJson({ error: "Wallet address required" }, 400);

      const creditAmount = parseFloat(String(body.creditAmount ?? "0"));

      // Update per-wallet list
      const walletOrders = ((await store.get(`fiat-orders-${wallet}`, { type: "json" })) ?? []) as FiatOrder[];
      const widx = walletOrders.findIndex((o) => o.id === orderId);
      if (widx === -1) return secureJson({ error: "Order not found for this wallet" }, 404);
      if (walletOrders[widx].status !== "pending") {
        return secureJson({ error: "Order is not pending" }, 400);
      }

      const finalCredit = creditAmount > 0 ? creditAmount : walletOrders[widx].estimatedCrypto;
      walletOrders[widx].status = "approved";
      walletOrders[widx].creditAmount = finalCredit;
      walletOrders[widx].processedAt = new Date().toISOString();
      await store.setJSON(`fiat-orders-${wallet}`, walletOrders);

      // Update global list
      const allOrders = ((await store.get("fiat-orders", { type: "json" })) ?? []) as FiatOrder[];
      const aidx = allOrders.findIndex((o) => o.id === orderId);
      if (aidx !== -1) {
        allOrders[aidx].status = "approved";
        allOrders[aidx].creditAmount = finalCredit;
        allOrders[aidx].processedAt = walletOrders[widx].processedAt;
        await store.setJSON("fiat-orders", allOrders);
      }

      // Credit the user's USDT balance
      const balance = ((await store.get(`balance-${wallet}`, { type: "json" })) ?? { usdt: 0 }) as { usdt: number };
      balance.usdt = parseFloat((balance.usdt + finalCredit).toFixed(2));
      await store.setJSON(`balance-${wallet}`, balance);

      await persistAuditLog("ADMIN_WRITE", {
        operation: "fiat-approve", wallet: `${wallet.slice(0, 8)}…`,
        orderId, creditAmount: finalCredit, ip,
      }, store);

      return secureJson({ success: true, creditAmount: finalCredit, newBalance: balance });
    }

    // ── Admin: reject a fiat order ───────────────────────────────────────────
    if (action === "reject") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "fiat-reject", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const orderId = sanitizeString(String(body.orderId ?? ""), 64);
      const wallet = sanitizeString(String(body.wallet ?? ""), 100).toLowerCase();
      if (!orderId) return secureJson({ error: "Order ID required" }, 400);
      if (!wallet) return secureJson({ error: "Wallet address required" }, 400);

      // Update per-wallet list
      const walletOrders = ((await store.get(`fiat-orders-${wallet}`, { type: "json" })) ?? []) as FiatOrder[];
      const widx = walletOrders.findIndex((o) => o.id === orderId);
      if (widx === -1) return secureJson({ error: "Order not found for this wallet" }, 404);
      if (walletOrders[widx].status !== "pending") {
        return secureJson({ error: "Order is not pending" }, 400);
      }
      walletOrders[widx].status = "rejected";
      walletOrders[widx].processedAt = new Date().toISOString();
      await store.setJSON(`fiat-orders-${wallet}`, walletOrders);

      // Update global list
      const allOrders = ((await store.get("fiat-orders", { type: "json" })) ?? []) as FiatOrder[];
      const aidx = allOrders.findIndex((o) => o.id === orderId);
      if (aidx !== -1) {
        allOrders[aidx].status = "rejected";
        allOrders[aidx].processedAt = walletOrders[widx].processedAt;
        await store.setJSON("fiat-orders", allOrders);
      }

      await persistAuditLog("ADMIN_WRITE", {
        operation: "fiat-reject", wallet: `${wallet.slice(0, 8)}…`, orderId, ip,
      }, store);

      return secureJson({ success: true });
    }

    return secureJson({ error: "Invalid action" }, 400);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/fiat",
  method: ["GET", "POST"],
};
