import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  getClientIp,
} from "../lib/security.js";

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

export default async (req: Request, context: Context) => {
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  const store = getStore({ name: "app-data", consistency: "strong" });
  const url = new URL(req.url);

  // ─── GET /api/wallet ─────────────────────────────────────────────────────
  // Returns deposit addresses (public read)
  if (req.method === "GET") {
    const walletParam = url.searchParams.get("wallet");

    // Get deposit addresses
    if (!walletParam) {
      const addresses = await store.get("deposit-addresses", { type: "json" });
      return secureJson(addresses || DEFAULT_ADDRESSES, 200, true);
    }

    // Get wallet info for a specific wallet
    const walletKey = sanitizeString(walletParam, 100).toLowerCase();
    if (!walletKey) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }

    const [user, balance] = await Promise.all([
      store.get(`user-${walletKey}`, { type: "json" }),
      store.get(`balance-${walletKey}`, { type: "json" }),
    ]);

    return secureJson({
      wallet: walletKey,
      user: user || null,
      balance: balance || { usdt: 0 },
    }, 200, true);
  }

  // ─── POST /api/wallet ─────────────────────────────────────────────────────
  // Admin-only: update deposit addresses
  if (req.method === "POST") {
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "update-wallet-addresses", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    const { action } = body;

    // Update deposit addresses
    if (action === "update-addresses" || !action) {
      const newAddresses: Record<string, string> = {};

      for (const network of VALID_NETWORKS) {
        const addr = body[network] as string | undefined;
        if (addr !== undefined && addr !== "") {
          const cleanAddr = sanitizeString(addr, 100);
          const pattern = ADDRESS_PATTERNS[network];
          if (pattern && !pattern.test(cleanAddr)) {
            return secureJson(
              { error: `Invalid address format for network ${network}` },
              400
            );
          }
          newAddresses[network] = cleanAddr;
        }
      }

      // Merge with existing
      const existing = ((await store.get("deposit-addresses", { type: "json" })) || DEFAULT_ADDRESSES) as Record<string, string>;
      const updated = { ...existing, ...newAddresses };
      await store.setJSON("deposit-addresses", updated);

      auditLog("ADMIN_WRITE", { operation: "update-wallet-addresses", networks: Object.keys(newAddresses), ip });
      return secureJson(updated);
    }

    return secureJson({ error: "Invalid action" }, 400);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/wallet",
  method: ["GET", "POST"],
};
