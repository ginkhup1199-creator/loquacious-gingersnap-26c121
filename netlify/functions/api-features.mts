import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  auditLog,
  persistAuditLog,
  getClientIp,
} from "../lib/security.js";

const DEFAULTS = {
  fiat: true,
  send: true,
  swap: true,
  trade: true,
  binary: true,
  ai: true,
  earn: true,
};

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const features = await store.get("features", { type: "json" });
    return secureJson(features || DEFAULTS, 200, true);
  }

  if (req.method === "POST") {
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "update-features", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json() as Record<string, unknown>;
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    // Load existing so omitted flags are not lost
    const existing = ((await store.get("features", { type: "json" })) || DEFAULTS) as Record<string, boolean>;
    const merged: Record<string, boolean> = { ...existing };
    for (const key of Object.keys(DEFAULTS)) {
      if (key in body) merged[key] = Boolean(body[key]);
    }
    await store.setJSON("features", merged);
    await persistAuditLog("ADMIN_WRITE", { operation: "update-features", ip }, store);
    return secureJson(merged);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/features",
  method: ["GET", "POST"],
};
