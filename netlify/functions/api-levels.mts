import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  auditLog,
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
  { id: 1, name: "Starter", capital: 200, dailyProfit: 2.5, duration: 7 },
  { id: 2, name: "Advanced", capital: 1000, dailyProfit: 3.5, duration: 14 },
  { id: 3, name: "Pro", capital: 5000, dailyProfit: 5.0, duration: 21 },
  { id: 4, name: "Elite", capital: 10000, dailyProfit: 6.5, duration: 30 },
  { id: 5, name: "Whale", capital: 50000, dailyProfit: 8.0, duration: 30 },
];

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

    auditLog("ADMIN_WRITE", { operation: "update-levels", ip });

    const body = await req.json();
    if (body.binaryLevels) {
      await store.setJSON("binary-levels", body.binaryLevels);
    }
    if (body.aiLevels) {
      await store.setJSON("ai-levels", body.aiLevels);
    }
    return secureJson({ success: true });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/levels",
  method: ["GET", "POST"],
};
