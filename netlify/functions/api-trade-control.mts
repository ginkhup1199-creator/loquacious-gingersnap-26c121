import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  auditLog,
  getClientIp,
} from "../lib/security.js";
import { normalizeWallet, parseJsonObject } from "../lib/validation.js";

const ALLOWED_OUTCOMES = ["random", "win", "lose"] as const;
type Outcome = (typeof ALLOWED_OUTCOMES)[number];

function parseOutcome(value: unknown): Outcome {
  const outcome = String(value ?? "") as Outcome;
  return ALLOWED_OUTCOMES.includes(outcome) ? outcome : "random";
}

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
      // No wallet specified — return the global setting
      const globalCtrl = await store.get("trade-control-__GLOBAL__", { type: "json" });
      return secureJson(globalCtrl || { outcome: "random" });
    }
    const safeWallet = normalizeWallet(String(wallet));
    if (!safeWallet) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }
    const control = await store.get(`trade-control-${safeWallet}`, { type: "json" });
    return secureJson(control || { outcome: "random" });
  }

  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await parseJsonObject(req);
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }
    const wallet = body.wallet;
    const outcome = body.outcome;

    // Allow __GLOBAL__ as special key for global outcome override
    const rawWallet = String(wallet ?? "");
    const safeWallet = rawWallet === "__GLOBAL__"
      ? "__GLOBAL__"
      : normalizeWallet(rawWallet);
    if (!safeWallet) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }

    const safeOutcome = parseOutcome(outcome);

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
  path: "/api/v2/trade-control",
  method: ["GET", "POST"],
};
