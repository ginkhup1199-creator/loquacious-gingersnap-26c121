import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  getClientIp,
} from "../lib/security.js";

const DEFAULT_SETTINGS = {
  swapFee: 0.5,
  binaryPayout: 85,
  btcStakingApy: 12.5,
};

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const settings = await store.get("settings", { type: "json" });
    return secureJson(settings || DEFAULT_SETTINGS, 200, true);
  }

  if (req.method === "POST") {
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "update-settings", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    auditLog("ADMIN_WRITE", { operation: "update-settings", ip });

    const body = await req.json();
    // Only accept known numeric settings
    const sanitized: Record<string, number> = {};
    for (const key of Object.keys(DEFAULT_SETTINGS)) {
      if (key in body) {
        const val = parseFloat(body[key]);
        if (!isNaN(val) && val >= 0) sanitized[key] = val;
      }
    }
    await store.setJSON("settings", sanitized);
    return secureJson(sanitized);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/settings",
  method: ["GET", "POST"],
};
