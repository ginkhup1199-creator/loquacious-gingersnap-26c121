import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import crypto from "node:crypto";

const DEFAULT_ADDRESSES: Record<string, string> = {
  TRC20: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
  ERC20: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  BSC: "0x55d398326f99059fF775485246999027B3197955",
  SOL: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
  BTC: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
};

const VALID_NETWORKS = ["TRC20", "ERC20", "BSC", "SOL", "BTC"];

// Address format validators
const ADDRESS_PATTERNS: Record<string, RegExp> = {
  TRC20: /^T[1-9A-HJ-NP-Za-km-z]{33}$/,
  ERC20: /^0x[0-9a-fA-F]{40}$/,
  BSC: /^0x[0-9a-fA-F]{40}$/,
  SOL: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
  BTC: /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}$/,
};

function auditLog(action: string, details: Record<string, unknown>): void {
  console.log(`[AUDIT] ${JSON.stringify({ timestamp: new Date().toISOString(), action, ...details })}`);
}

function hashForLog(token: string): string {
  if (!token) return "null";
  return token.slice(0, 4) + "***[" + token.length + "]";
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

// Sanitize string inputs
function sanitize(input: unknown, maxLen = 200): string {
  if (typeof input !== "string") return "";
  return input.replace(/<[^>]*>/g, "").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim().slice(0, maxLen);
}

export default async (req: Request, context: Context) => {
  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) {
    return Response.json({ error: "Admin token not configured" }, { status: 503 });
  }

  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(req, context);
  const url = new URL(req.url);

  // ─── GET /api/wallet ─────────────────────────────────────────────────────
  // Returns deposit addresses (public read)
  if (req.method === "GET") {
    const walletParam = url.searchParams.get("wallet");

    // Get deposit addresses
    if (!walletParam) {
      const addresses = await store.get("deposit-addresses", { type: "json" });
      return Response.json(addresses || DEFAULT_ADDRESSES);
    }

    // Get wallet info for a specific wallet
    const walletKey = sanitize(walletParam, 100).toLowerCase();
    if (!walletKey) {
      return Response.json({ error: "Invalid wallet address" }, { status: 400 });
    }

    const [user, balance] = await Promise.all([
      store.get(`user-${walletKey}`, { type: "json" }),
      store.get(`balance-${walletKey}`, { type: "json" }),
    ]);

    return Response.json({
      wallet: walletKey,
      user: user || null,
      balance: balance || { usdt: 0 },
    });
  }

  // ─── POST /api/wallet ─────────────────────────────────────────────────────
  // Admin-only: update deposit addresses
  if (req.method === "POST") {
    if (!validateAdminToken(req)) {
      auditLog("UNAUTHORIZED_ACCESS", { ip, resource: "wallet/addresses" });
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }

    const { action } = body;

    // Update deposit addresses
    if (action === "update-addresses" || !action) {
      const newAddresses: Record<string, string> = {};

      for (const network of VALID_NETWORKS) {
        const addr = body[network] as string | undefined;
        if (addr !== undefined) {
          const cleanAddr = sanitize(addr, 100);
          const pattern = ADDRESS_PATTERNS[network];
          if (pattern && !pattern.test(cleanAddr)) {
            return Response.json(
              { error: `Invalid address format for network ${network}` },
              { status: 400 }
            );
          }
          newAddresses[network] = cleanAddr;
        }
      }

      // Merge with existing
      const existing = ((await store.get("deposit-addresses", { type: "json" })) || DEFAULT_ADDRESSES) as Record<string, string>;
      const updated = { ...existing, ...newAddresses };
      await store.setJSON("deposit-addresses", updated);

      auditLog("WALLET_ADDRESS_UPDATED", { ip, networks: Object.keys(newAddresses) });
      return Response.json(updated);
    }

    return Response.json({ error: "Invalid action" }, { status: 400 });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/wallet",
  method: ["GET", "POST"],
};
