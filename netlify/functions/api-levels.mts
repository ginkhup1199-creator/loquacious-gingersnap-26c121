import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import crypto from "node:crypto";

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

function sanitize(input: unknown, maxLen = 200): string {
  if (typeof input !== "string") return "";
  let s = input.slice(0, maxLen).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
  let prev: string;
  do {
    prev = s;
    s = s.replace(/<[^>]*>/g, "");
  } while (s !== prev);
  return s.replace(/[<>]/g, "");
}

function auditLog(action: string, details: Record<string, unknown>): void {
  console.log(`[AUDIT] ${JSON.stringify({ timestamp: new Date().toISOString(), action, ...details })}`);
}

function getClientIp(req: Request, context: Context): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-nf-client-connection-ip") ||
    context.ip ||
    "unknown";
}

function validateAdminToken(req: Request): boolean {
  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) return false;
  const provided = req.headers.get("X-Admin-Token");
  if (!provided) return false;
  try {
    const a = Buffer.from(provided);
    const b = Buffer.from(adminToken);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

interface Level {
  id: number;
  name: string;
  capital: number;
  [key: string]: unknown;
}

function sanitizeLevels(levels: unknown[]): Level[] {
  return levels
    .filter((l): l is Record<string, unknown> => l !== null && typeof l === "object" && !Array.isArray(l))
    .map((l) => ({
      id: parseInt(String(l.id), 10) || 0,
      name: sanitize(l.name as string, 50),
      capital: Math.max(0, parseFloat(String(l.capital)) || 0),
      ...(l.tradingTime !== undefined && { tradingTime: Math.max(0, parseInt(String(l.tradingTime), 10) || 0) }),
      ...(l.profitPercent !== undefined && { profitPercent: Math.min(100, Math.max(0, parseFloat(String(l.profitPercent)) || 0)) }),
      ...(l.dailyProfit !== undefined && { dailyProfit: Math.min(50, Math.max(0, parseFloat(String(l.dailyProfit)) || 0)) }),
      ...(l.duration !== undefined && { duration: Math.max(1, parseInt(String(l.duration), 10) || 1) }),
    }))
    .slice(0, 20); // max 20 levels
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) {
    return Response.json({ error: "Admin token not configured" }, { status: 503 });
  }

  const ip = getClientIp(req, context);

  if (req.method === "GET") {
    const [binaryLevels, aiLevels] = await Promise.all([
      store.get("binary-levels", { type: "json" }),
      store.get("ai-levels", { type: "json" }),
    ]);
    return Response.json({
      binaryLevels: binaryLevels || DEFAULT_BINARY_LEVELS,
      aiLevels: aiLevels || DEFAULT_AI_LEVELS,
    });
  }

  if (req.method === "POST") {
    if (!validateAdminToken(req)) {
      auditLog("UNAUTHORIZED_ACCESS", { ip, resource: "levels/update" });
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }

    if (body.binaryLevels && Array.isArray(body.binaryLevels)) {
      await store.setJSON("binary-levels", sanitizeLevels(body.binaryLevels));
    }
    if (body.aiLevels && Array.isArray(body.aiLevels)) {
      await store.setJSON("ai-levels", sanitizeLevels(body.aiLevels));
    }

    auditLog("LEVELS_UPDATED", { ip });
    return Response.json({ success: true });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/levels",
  method: ["GET", "POST"],
};
