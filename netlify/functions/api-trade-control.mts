import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  getClientIp,
} from "../lib/security.mjs";

const ALLOWED_OUTCOMES = ["random", "win", "lose"] as const;
type Outcome = (typeof ALLOWED_OUTCOMES)[number];

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  const sessionResult = await validateAdminSession(req, store);
  if (!sessionResult.valid) {
    auditLog("AUTH_FAILURE", { operation: "trade-control", reason: sessionResult.reason, ip });
    return secureJson({ error: "Unauthorized" }, 401);
  }

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");
    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }
    const safeWallet = sanitizeString(String(wallet), 100).toLowerCase();
    if (!safeWallet) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }
    const control = await store.get(`trade-control-${safeWallet}`, { type: "json" });
    return secureJson(control || { outcome: "random" });
  }

  if (req.method === "POST") {
    let body: any;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }
    const { wallet, outcome } = body;

    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }
    const safeWallet = sanitizeString(String(wallet), 100).toLowerCase();
    if (!safeWallet) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }

    const safeOutcome: Outcome = ALLOWED_OUTCOMES.includes(String(outcome) as Outcome)
      ? (String(outcome) as Outcome)
      : "random";

    auditLog("ADMIN_WRITE", {
      operation: "set-trade-control",
      wallet: `${safeWallet.slice(0, 8)}…`,
      outcome: safeOutcome,
      ip,
    });

    await store.setJSON(`trade-control-${safeWallet}`, { outcome: safeOutcome });
    return secureJson({ success: true, outcome: safeOutcome });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/trade-control",
  method: ["GET", "POST"],
};
