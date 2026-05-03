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

const BONUS_KEY = "bonus-config";

const DEFAULT_BONUS_CONFIG = {
  firstRechargeBonusPercent: 10,
  couponTiers: [
    { id: 1, minDeposit: 100, couponCode: "WELCOME5", bonusPercent: 5 },
    { id: 2, minDeposit: 500, couponCode: "BOOST10", bonusPercent: 10 },
    { id: 3, minDeposit: 1000, couponCode: "VIP15", bonusPercent: 15 },
  ],
  updatedAt: null,
};

export default async (req: Request, context: Context) => {
  const ip = getClientIp(context);
  const store = getStore({ name: "app-data", consistency: "strong" });

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const current = (await store.get(BONUS_KEY, { type: "json" })) || DEFAULT_BONUS_CONFIG;
    return secureJson(current, 200, true);
  }

  if (req.method === "POST") {
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "update-bonus", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    let body: Record<string, unknown>;
    try {
      body = await parseJsonObject(req);
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    const firstRechargeBonusPercent = Math.max(
      0,
      Math.min(100, parseFloat(String(body.firstRechargeBonusPercent ?? 10)) || 0),
    );

    const sourceTiers = Array.isArray(body.couponTiers) ? body.couponTiers : DEFAULT_BONUS_CONFIG.couponTiers;
    const couponTiers = sourceTiers.slice(0, 10).map((tier: any, idx: number) => ({
      id: Number(tier.id) || idx + 1,
      minDeposit: Math.max(1, Math.min(1_000_000, parseFloat(String(tier.minDeposit ?? 100)) || 100)),
      couponCode: (sanitizeString(String(tier.couponCode ?? ""), 24) || `BONUS${idx + 1}`).toUpperCase(),
      bonusPercent: Math.max(0, Math.min(100, parseFloat(String(tier.bonusPercent ?? 0)) || 0)),
    }));

    const payload = {
      firstRechargeBonusPercent,
      couponTiers,
      updatedAt: new Date().toISOString(),
    };

    await store.setJSON(BONUS_KEY, payload);
    await persistAuditLog("ADMIN_WRITE", { operation: "update-bonus", tiers: couponTiers.length, ip }, store);
    return secureJson(payload, 200);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/v2/bonus",
  method: ["GET", "POST"],
};
