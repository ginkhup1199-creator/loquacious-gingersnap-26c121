import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAnyAdminSession,
  hasPermission,
  secureJson,
  sanitizeString,
  auditLog,
  persistAuditLog,
  getClientIp,
} from "../lib/security.mjs";

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
    const sessionResult = await validateAnyAdminSession(req, store);
    if (!sessionResult.valid || !hasPermission(sessionResult, "settings")) {
      auditLog("AUTH_FAILURE", { operation: "update-settings", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    // Load existing settings so omitted keys are not lost
    const existing = ((await store.get("settings", { type: "json" })) || DEFAULT_SETTINGS) as Record<string, number>;
    const merged: Record<string, number> = { ...existing };
    for (const key of Object.keys(DEFAULT_SETTINGS)) {
      if (key in body) {
        const val = parseFloat(body[key] as string);
        if (!isNaN(val) && val >= 0) merged[key] = val;
      }
    }
    await store.setJSON("settings", merged);
    await persistAuditLog("ADMIN_WRITE", { operation: "update-settings", ip }, store);
    return secureJson(merged);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/settings",
  method: ["GET", "POST"],
};
