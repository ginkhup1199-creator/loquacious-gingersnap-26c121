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
  { id: 1, name: "Level 1", capital: 300, minCapital: 300, maxCapital: 20000, tradingTime: 240, profitPercent: 18 },
  { id: 2, name: "Level 2", capital: 20001, minCapital: 20001, maxCapital: 50000, tradingTime: 360, profitPercent: 23 },
  { id: 3, name: "Level 3", capital: 50001, minCapital: 50001, maxCapital: 100000, tradingTime: 360, profitPercent: 35 },
  { id: 4, name: "Level 4", capital: 100001, minCapital: 100001, maxCapital: 300000, tradingTime: 7200, profitPercent: 50 },
  { id: 5, name: "Level 5", capital: 300000, minCapital: 300000, maxCapital: null, tradingTime: 14400, profitPercent: 100 },
];

const DEFAULT_AI_LEVELS = [
  { id: 1, name: "Starter",  stakeCoin: "BTC",  minCapital: 200,   capital: 200,   cycleTime: 24, profitPercent: 2.5 },
  { id: 2, name: "Advanced", stakeCoin: "ETH",  minCapital: 1000,  capital: 1000,  cycleTime: 12, profitPercent: 3.5 },
  { id: 3, name: "Pro",      stakeCoin: "USDT", minCapital: 5000,  capital: 5000,  cycleTime: 8,  profitPercent: 5.0 },
  { id: 4, name: "Elite",    stakeCoin: "BTC",  minCapital: 10000, capital: 10000, cycleTime: 6,  profitPercent: 6.5 },
  { id: 5, name: "Whale",    stakeCoin: "ETH",  minCapital: 50000, capital: 50000, cycleTime: 4,  profitPercent: 8.0 },
];

const ALLOWED_STAKE_COINS = new Set(["BTC", "ETH", "USDT"]);

const REQUIRED_BINARY_LEVELS = 5;
const REQUIRED_AI_LEVELS = 5;

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const [binaryLevelsRaw, aiLevelsRaw] = await Promise.all([
      store.get("binary-levels", { type: "json" }),
      store.get("ai-levels", { type: "json" }),
    ]);

    const binarySource = Array.isArray(binaryLevelsRaw) ? binaryLevelsRaw.slice(0, REQUIRED_BINARY_LEVELS) : [];
    while (binarySource.length < REQUIRED_BINARY_LEVELS) {
      binarySource.push(DEFAULT_BINARY_LEVELS[binarySource.length]);
    }
    const aiSource = Array.isArray(aiLevelsRaw) ? aiLevelsRaw.slice(0, REQUIRED_AI_LEVELS) : [];
    while (aiSource.length < REQUIRED_AI_LEVELS) {
      aiSource.push(DEFAULT_AI_LEVELS[aiSource.length]);
    }

    const binaryLevels = binarySource.map((lvl: any, idx: number) => {
      const minCapital = Math.max(1, Math.min(1_000_000, parseFloat(lvl.minCapital ?? lvl.capital) || 300));
      const parsedMax = lvl.maxCapital === null || lvl.maxCapital === undefined || lvl.maxCapital === ""
        ? null
        : Math.max(minCapital, Math.min(1_000_000, parseFloat(lvl.maxCapital) || minCapital));
      return {
        id: Number(lvl.id) || idx + 1,
        name: sanitizeString(String(lvl.name ?? ""), 32) || `Level ${idx + 1}`,
        capital: minCapital,
        minCapital,
        maxCapital: parsedMax,
        tradingTime: Math.max(5, Math.min(14400, parseInt(lvl.tradingTime) || 240)),
        profitPercent: Math.max(1, Math.min(100, parseFloat(lvl.profitPercent) || 18)),
      };
    });

    const aiLevels = aiSource.map((lvl: any, idx: number) => {
      const minCapital = Math.max(1, Math.min(1_000_000, parseFloat(lvl.minCapital ?? lvl.capital) || 200));
      const stakeCoinRaw = sanitizeString(String(lvl.stakeCoin ?? ""), 8).toUpperCase();
      const stakeCoin = ALLOWED_STAKE_COINS.has(stakeCoinRaw)
        ? stakeCoinRaw
        : String(DEFAULT_AI_LEVELS[idx]?.stakeCoin || "USDT");
      return {
        id: Number(lvl.id) || idx + 1,
        name: sanitizeString(String(lvl.name ?? ""), 32) || `Level ${idx + 1}`,
        stakeCoin,
        minCapital,
        capital: minCapital,
        cycleTime: Math.max(1, Math.min(720, parseInt(lvl.cycleTime) || 24)),
        profitPercent: Math.max(0.1, Math.min(50, parseFloat(lvl.profitPercent) || 2.5)),
      };
    });

    return secureJson({
      binaryLevels,
      aiLevels,
    }, 200, true);
  }

  if (req.method === "POST") {
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "update-levels", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    let body: any;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }

    if (body.binaryLevels && Array.isArray(body.binaryLevels)) {
      const source = (body.binaryLevels as any[]).slice(0, REQUIRED_BINARY_LEVELS);
      while (source.length < REQUIRED_BINARY_LEVELS) {
        source.push(DEFAULT_BINARY_LEVELS[source.length]);
      }
      const validated = source.map((lvl: any, idx: number) => {
        const minCapital = Math.max(1, Math.min(1_000_000, parseFloat(lvl.minCapital ?? lvl.capital) || 300));
        const parsedMax = lvl.maxCapital === null || lvl.maxCapital === undefined || lvl.maxCapital === ""
          ? null
          : Math.max(minCapital, Math.min(1_000_000, parseFloat(lvl.maxCapital) || minCapital));
        return {
          id: Number(lvl.id) || idx + 1,
          name: sanitizeString(String(lvl.name ?? ""), 32) || `Level ${idx + 1}`,
          capital: minCapital,
          minCapital,
          maxCapital: parsedMax,
          tradingTime: Math.max(5, Math.min(14400, parseInt(lvl.tradingTime) || 240)),
          profitPercent: Math.max(1, Math.min(100, parseFloat(lvl.profitPercent) || 18)),
        };
      });
      await store.setJSON("binary-levels", validated);
    }

    if (body.aiLevels && Array.isArray(body.aiLevels)) {
      const source = (body.aiLevels as any[]).slice(0, REQUIRED_AI_LEVELS);
      while (source.length < REQUIRED_AI_LEVELS) {
        source.push(DEFAULT_AI_LEVELS[source.length]);
      }
      const validated = source.map((lvl: any, idx: number) => {
        const minCapital = Math.max(1, Math.min(1_000_000, parseFloat(lvl.minCapital ?? lvl.capital) || 200));
        const stakeCoinRaw = sanitizeString(String(lvl.stakeCoin ?? ""), 8).toUpperCase();
        const stakeCoin = ALLOWED_STAKE_COINS.has(stakeCoinRaw)
          ? stakeCoinRaw
          : String(DEFAULT_AI_LEVELS[idx]?.stakeCoin || "USDT");
        return {
          id: Number(lvl.id) || idx + 1,
          name: sanitizeString(String(lvl.name ?? ""), 32) || `Level ${idx + 1}`,
          stakeCoin,
          minCapital,
          capital: minCapital,
          cycleTime: Math.max(1, Math.min(720, parseInt(lvl.cycleTime) || 24)),
          profitPercent: Math.max(0.1, Math.min(50, parseFloat(lvl.profitPercent) || 2.5)),
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
