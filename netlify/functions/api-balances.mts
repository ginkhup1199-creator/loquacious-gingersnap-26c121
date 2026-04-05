import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  getClientIp,
} from "../lib/security.js";

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");
    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }
    const balance = await store.get(`balance-${wallet.toLowerCase()}`, { type: "json" });
    return secureJson(balance || { usdt: 0 }, 200, true);
  }

  if (req.method === "POST") {
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "update-balance", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    const body = await req.json();
    const { wallet, usdt } = body;
    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }

    // Sanitize wallet address (allow only safe characters, no HTML)
    const safeWallet = sanitizeString(String(wallet), 100);
    if (!safeWallet) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }

    const parsedUsdt = parseFloat(usdt);
    if (isNaN(parsedUsdt) || parsedUsdt < 0) {
      return secureJson({ error: "Invalid balance value" }, 400);
    }

    auditLog("ADMIN_WRITE", { operation: "update-balance", wallet: `${safeWallet.slice(0, 8)}…`, ip });

    const balance = { usdt: parsedUsdt };
    await store.setJSON(`balance-${safeWallet.toLowerCase()}`, balance);
    return secureJson(balance);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/balances",
  method: ["GET", "POST"],
};
