import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import crypto from "node:crypto";

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

// Rate limiter
const rateLimitMap = new Map<string, { count: number; windowStart: number }>();
function isRateLimited(ip: string): boolean {
  const now = Date.now();
  for (const [k, v] of rateLimitMap.entries()) {
    if (now - v.windowStart > 60000) rateLimitMap.delete(k);
  }
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > 60000) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return false;
  }
  entry.count += 1;
  return entry.count > 30;
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) {
    return Response.json({ error: "Admin token not configured" }, { status: 503 });
  }

  const ip = getClientIp(req, context);

  if (isRateLimited(ip)) {
    auditLog("RATE_LIMIT_EXCEEDED", { ip, path: "/api/balances" });
    return Response.json({ error: "Too many requests" }, { status: 429 });
  }

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");
    if (!wallet) {
      return Response.json({ error: "Wallet address required" }, { status: 400 });
    }
    const walletKey = sanitize(wallet, 100).toLowerCase();
    if (!walletKey) {
      return Response.json({ error: "Invalid wallet address" }, { status: 400 });
    }
    const balance = await store.get(`balance-${walletKey}`, { type: "json" });
    return Response.json(balance || { usdt: 0 });
  }

  if (req.method === "POST") {
    if (!validateAdminToken(req)) {
      auditLog("UNAUTHORIZED_ACCESS", { ip, resource: "balances/update" });
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }

    const wallet = sanitize(body.wallet as string, 100).toLowerCase();
    if (!wallet) {
      return Response.json({ error: "Wallet address required" }, { status: 400 });
    }

    const rawUsdt = parseFloat(body.usdt as string);
    if (isNaN(rawUsdt) || rawUsdt < 0) {
      return Response.json({ error: "Invalid balance value" }, { status: 400 });
    }

    const existing = ((await store.get(`balance-${wallet}`, { type: "json" })) || { usdt: 0 }) as { usdt: number };
    const balance = { usdt: rawUsdt };
    await store.setJSON(`balance-${wallet}`, balance);

    auditLog("BALANCE_UPDATED", { ip, wallet, prevBalance: existing.usdt, newBalance: rawUsdt });
    return Response.json(balance);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/balances",
  method: ["GET", "POST"],
};
