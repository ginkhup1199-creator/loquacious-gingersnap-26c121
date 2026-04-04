import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import crypto from "node:crypto";

const VALID_COINS = ["USDT", "USDC", "BTC", "ETH", "BNB", "SOL", "XRP", "ADA", "AVAX", "DOGE"];
const VALID_NETWORKS = ["TRC20", "ERC20", "BSC", "SOL", "BTC"];
const VALID_STATUSES = ["Pending", "Approved", "Rejected", "Completed"];

function sanitize(input: unknown, maxLen = 200): string {
  if (typeof input !== "string") return "";
  return input.replace(/<[^>]*>/g, "").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim().slice(0, maxLen);
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
  return entry.count > 20;
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) {
    return Response.json({ error: "Admin token not configured" }, { status: 503 });
  }

  const ip = getClientIp(req, context);

  if (isRateLimited(ip)) {
    auditLog("RATE_LIMIT_EXCEEDED", { ip, path: "/api/withdrawals" });
    return Response.json({ error: "Too many requests" }, { status: 429 });
  }

  if (req.method === "GET") {
    const withdrawals = await store.get("withdrawals", { type: "json" });
    return Response.json(withdrawals || []);
  }

  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }

    const { action } = body;

    if (action === "add") {
      const coin = sanitize(body.coin as string, 10).toUpperCase();
      const network = sanitize(body.network as string, 10).toUpperCase();
      const address = sanitize(body.address as string, 100);
      const amount = parseFloat(body.amount as string);

      if (!VALID_COINS.includes(coin)) {
        return Response.json({ error: "Invalid coin" }, { status: 400 });
      }
      if (!VALID_NETWORKS.includes(network)) {
        return Response.json({ error: "Invalid network" }, { status: 400 });
      }
      if (!address || address.length < 10) {
        return Response.json({ error: "Invalid withdrawal address" }, { status: 400 });
      }
      if (isNaN(amount) || amount <= 0) {
        return Response.json({ error: "Invalid withdrawal amount" }, { status: 400 });
      }

      const existing = ((await store.get("withdrawals", { type: "json" })) || []) as Array<Record<string, unknown>>;
      const newWithdrawal = {
        id: crypto.randomUUID(),
        coin,
        network,
        address,
        amount,
        date: new Date().toISOString().split("T")[0],
        status: "Pending",
        createdAt: new Date().toISOString(),
      };
      existing.push(newWithdrawal);
      await store.setJSON("withdrawals", existing);

      auditLog("WITHDRAWAL_REQUESTED", { ip, coin, network, amount, address: address.slice(0, 10) + "***" });
      return Response.json(newWithdrawal);
    }

    if (action === "process") {
      if (!validateAdminToken(req)) {
        auditLog("UNAUTHORIZED_ACCESS", { ip, resource: "withdrawals/process" });
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }

      const withdrawalId = sanitize(body.id as string, 100);
      const newStatus = sanitize(body.status as string, 20) || "Completed";

      if (!VALID_STATUSES.includes(newStatus)) {
        return Response.json({ error: "Invalid status" }, { status: 400 });
      }

      const existing = ((await store.get("withdrawals", { type: "json" })) || []) as Array<Record<string, unknown>>;

      if (newStatus === "Completed" || newStatus === "Rejected") {
        const updated = existing.filter((w) => w.id !== withdrawalId);
        await store.setJSON("withdrawals", updated);
      } else {
        const idx = existing.findIndex((w) => w.id === withdrawalId);
        if (idx !== -1) {
          existing[idx].status = newStatus;
          await store.setJSON("withdrawals", existing);
        }
      }

      const logAction = newStatus === "Completed" ? "WITHDRAWAL_PROCESSED" : "WITHDRAWAL_REJECTED";
      auditLog(logAction, { ip, withdrawalId, status: newStatus });
      return Response.json({ success: true });
    }

    return Response.json({ error: "Invalid action" }, { status: 400 });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/withdrawals",
  method: ["GET", "POST"],
};
