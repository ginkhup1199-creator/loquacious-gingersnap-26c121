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

const DEFAULT_BINARY_LEVELS = [
  { id: 1, name: "Bronze", capital: 100, tradingTime: 60, profitPercent: 85 },
  { id: 2, name: "Silver", capital: 500, tradingTime: 120, profitPercent: 88 },
  { id: 3, name: "Gold", capital: 2000, tradingTime: 180, profitPercent: 90 },
  { id: 4, name: "Platinum", capital: 5000, tradingTime: 300, profitPercent: 92 },
  { id: 5, name: "Diamond", capital: 10000, tradingTime: 600, profitPercent: 95 },
];

const DEFAULT_AI_LEVELS = [
  { id: 1, name: "Starter",  capital: 200,   cycleTime: 24, profitPercent: 2.5 },
  { id: 2, name: "Advanced", capital: 1000,  cycleTime: 12, profitPercent: 3.5 },
  { id: 3, name: "Pro",      capital: 5000,  cycleTime: 8,  profitPercent: 5.0 },
  { id: 4, name: "Elite",    capital: 10000, cycleTime: 6,  profitPercent: 6.5 },
  { id: 5, name: "Whale",    capital: 50000, cycleTime: 4,  profitPercent: 8.0 },
];

const MAX_BINARY_LEVELS = 10;
const MAX_AI_LEVELS = 10;

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const [binaryLevels, aiLevels] = await Promise.all([
      store.get("binary-levels", { type: "json" }),
      store.get("ai-levels", { type: "json" }),
    ]);
    return secureJson({
      binaryLevels: binaryLevels || DEFAULT_BINARY_LEVELS,
      aiLevels: aiLevels || DEFAULT_AI_LEVELS,
    }, 200, true);
  }

  if (req.method === "POST") {
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "update-levels", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    const body = await req.json();

    if (body.binaryLevels && Array.isArray(body.binaryLevels)) {
      const validated = (body.binaryLevels as any[]).slice(0, MAX_BINARY_LEVELS).map((lvl: any, idx: number) => ({
        id: Number(lvl.id) || idx + 1,
        name: sanitizeString(String(lvl.name ?? ""), 32) || `Level ${idx + 1}`,
        capital:       Math.max(1,   Math.min(1_000_000, parseFloat(lvl.capital)      || 100)),
        tradingTime:   Math.max(5,   Math.min(3600,      parseInt(lvl.tradingTime)    || 60)),
        profitPercent: Math.max(1,   Math.min(99,        parseFloat(lvl.profitPercent) || 85)),
      }));
      await store.setJSON("binary-levels", validated);
    }

    if (body.aiLevels && Array.isArray(body.aiLevels)) {
      const validated = (body.aiLevels as any[]).slice(0, MAX_AI_LEVELS).map((lvl: any, idx: number) => ({
        id: Number(lvl.id) || idx + 1,
        name: sanitizeString(String(lvl.name ?? ""), 32) || `Level ${idx + 1}`,
        capital:       Math.max(1,   Math.min(1_000_000, parseFloat(lvl.capital)       || 200)),
        cycleTime:     Math.max(1,   Math.min(720,        parseInt(lvl.cycleTime)       || 24)),
        profitPercent: Math.max(0.1, Math.min(50,         parseFloat(lvl.profitPercent) || 2.5)),
      }));
      await store.setJSON("ai-levels", validated);
    }

    await persistAuditLog("ADMIN_WRITE", { operation: "update-levels", ip }, store);
    return secureJson({ success: true });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/levels",
  method: ["GET", "POST"],
};
