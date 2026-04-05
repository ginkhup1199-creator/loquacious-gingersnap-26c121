import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  auditLog,
  getClientIp,
} from "../lib/security.mjs";

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

    auditLog("ADMIN_WRITE", { operation: "update-features", ip });

    const body = await req.json() as Record<string, unknown>;
    // Only accept known boolean feature flags
    const sanitized: Record<string, boolean> = {};
    for (const key of Object.keys(DEFAULTS)) {
      if (key in body) sanitized[key] = Boolean(body[key]);
    }
    await store.setJSON("features", sanitized);
    return secureJson(sanitized);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/features",
  method: ["GET", "POST"],
};
