import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import crypto from "node:crypto";

const DEFAULTS = {
  fiat: true,
  send: true,
  swap: true,
  trade: true,
  binary: true,
  ai: true,
  earn: true,
};

const VALID_FEATURE_KEYS = Object.keys(DEFAULTS);

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

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) {
    return Response.json({ error: "Admin token not configured" }, { status: 503 });
  }

  const ip = getClientIp(req, context);

  if (req.method === "GET") {
    const features = await store.get("features", { type: "json" });
    return Response.json(features || DEFAULTS);
  }

  if (req.method === "POST") {
    if (!validateAdminToken(req)) {
      auditLog("UNAUTHORIZED_ACCESS", { ip, resource: "features/update" });
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }

    // Only allow valid feature keys with boolean values
    const sanitized: Record<string, boolean> = {};
    for (const key of VALID_FEATURE_KEYS) {
      if (key in body) {
        sanitized[key] = Boolean(body[key]);
      }
    }

    const updated = { ...DEFAULTS, ...sanitized };
    await store.setJSON("features", updated);

    auditLog("FEATURES_UPDATED", { ip, changes: sanitized });
    return Response.json(updated);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/features",
  method: ["GET", "POST"],
};
