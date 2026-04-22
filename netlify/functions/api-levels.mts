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
import { isRecord, parseJsonObject, toInteger, toNumber } from "../lib/validation.js";

const DEFAULT_BINARY_LEVELS = [
  { id: 1, name: "Level 1", capital: 300, minCapital: 300, maxCapital: 20000, tradingTime: 240, profitPercent: 18 },
  { id: 2, name: "Level 2", capital: 20001, minCapital: 20001, maxCapital: 50000, tradingTime: 360, profitPercent: 23 },
  { id: 3, name: "Level 3", capital: 50001, minCapital: 50001, maxCapital: 100000, tradingTime: 360, profitPercent: 35 },
  { id: 4, name: "Level 4", capital: 100001, minCapital: 100001, maxCapital: 300000, tradingTime: 7200, profitPercent: 50 },
  { id: 5, name: "Level 5", capital: 300001, minCapital: 300001, maxCapital: null, tradingTime: 14400, profitPercent: 100 },
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

type BinaryLevel = {
  id: number;
  name: string;
  capital: number;
  minCapital: number;
  maxCapital: number | null;
  tradingTime: number;
  profitPercent: number;
};

type AiLevel = {
  id: number;
  name: string;
  capital: number;
  cycleTime: number;
  profitPercent: number;
};

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "eventual" });
  const ip = getClientIp(context);

  if (req.method === "GET") {
    try {
      const [binaryLevels, aiLevels] = await Promise.all([
        store.get("binary-levels", { type: "json" }),
        store.get("ai-levels", { type: "json" }),
      ]);
      return secureJson({
        binaryLevels: binaryLevels || DEFAULT_BINARY_LEVELS,
        aiLevels: aiLevels || DEFAULT_AI_LEVELS,
      }, 200, true);
    } catch {
      return secureJson({
        binaryLevels: DEFAULT_BINARY_LEVELS,
        aiLevels: DEFAULT_AI_LEVELS,
      }, 200, true);
    }
  }

  if (req.method === "POST") {
    if (!process.env.ADMIN_TOKEN) {
      return secureJson({ error: "Admin token not configured" }, 503);
    }
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "update-levels", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    let body: Record<string, unknown>;
    try {
      body = await parseJsonObject(req);
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }

    if (body.binaryLevels && Array.isArray(body.binaryLevels)) {
      const validated: BinaryLevel[] = body.binaryLevels.slice(0, MAX_BINARY_LEVELS).map((lvl, idx) => {
        const level = isRecord(lvl) ? lvl : {};
        const minCapital = Math.max(1, Math.min(1_000_000, toNumber(level.minCapital ?? level.capital, 300)));
        const parsedMax = level.maxCapital === null || level.maxCapital === undefined || level.maxCapital === ""
          ? null
          : Math.max(minCapital, Math.min(1_000_000, toNumber(level.maxCapital, minCapital)));
        return {
          id: toInteger(level.id, idx + 1),
          name: sanitizeString(String(level.name ?? ""), 32) || `Level ${idx + 1}`,
          capital: minCapital,
          minCapital,
          maxCapital: parsedMax,
          tradingTime: Math.max(5, Math.min(14400, toInteger(level.tradingTime, 240))),
          profitPercent: Math.max(1, Math.min(100, toNumber(level.profitPercent, 18))),
        };
      });
      await store.setJSON("binary-levels", validated);
    }

    if (body.aiLevels && Array.isArray(body.aiLevels)) {
      const validated: AiLevel[] = body.aiLevels.slice(0, MAX_AI_LEVELS).map((lvl, idx) => {
        const level = isRecord(lvl) ? lvl : {};
        return {
          id: toInteger(level.id, idx + 1),
          name: sanitizeString(String(level.name ?? ""), 32) || `Level ${idx + 1}`,
          capital: Math.max(1, Math.min(1_000_000, toNumber(level.capital, 200))),
          cycleTime: Math.max(1, Math.min(720, toInteger(level.cycleTime, 24))),
          profitPercent: Math.max(0.1, Math.min(50, toNumber(level.profitPercent, 2.5))),
        };
      });
      await store.setJSON("ai-levels", validated);
    }

    await persistAuditLog("ADMIN_WRITE", { operation: "update-levels", ip }, store);
    return secureJson({ success: true });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/v2/levels",
  method: ["GET", "POST"],
};
