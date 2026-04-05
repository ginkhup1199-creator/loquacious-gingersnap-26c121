import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  getClientIp,
} from "../lib/security.mjs";

const DEFAULT_ADDRESSES: Record<string, string> = {
  TRC20: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
  ERC20: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  BSC: "0x55d398326f99059fF775485246999027B3197955",
  SOL: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
  BTC: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
};

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const addresses = await store.get("deposit-addresses", { type: "json" });
    return secureJson(addresses || DEFAULT_ADDRESSES, 200, true);
  }

  if (req.method === "POST") {
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "update-addresses", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    auditLog("ADMIN_WRITE", { operation: "update-addresses", ip });

    const body = await req.json() as Record<string, unknown>;
    // Sanitize all address values
    const sanitized: Record<string, string> = {};
    for (const [key, value] of Object.entries(body)) {
      const safeKey = sanitizeString(key, 16);
      const safeValue = sanitizeString(String(value ?? ""), 200);
      if (safeKey && safeValue) sanitized[safeKey] = safeValue;
    }
    await store.setJSON("deposit-addresses", sanitized);
    return secureJson(sanitized);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/addresses",
  method: ["GET", "POST"],
};
