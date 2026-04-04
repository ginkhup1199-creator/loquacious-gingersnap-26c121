import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import crypto from "node:crypto";

const DEFAULT_SETTINGS = {
  swapFee: 0.5,
  binaryPayout: 85,
  btcStakingApy: 12.5,
};

// Bounds for settings to prevent abuse
const SETTINGS_BOUNDS: Record<string, { min: number; max: number }> = {
  swapFee: { min: 0, max: 10 },
  binaryPayout: { min: 50, max: 99 },
  btcStakingApy: { min: 0, max: 100 },
};

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
    const settings = await store.get("settings", { type: "json" });
    return Response.json(settings || DEFAULT_SETTINGS);
  }

  if (req.method === "POST") {
    if (!validateAdminToken(req)) {
      auditLog("UNAUTHORIZED_ACCESS", { ip, resource: "settings/update" });
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }

    // Only allow known settings keys with validated numeric values
    const sanitized: Record<string, number> = {};
    for (const key of Object.keys(DEFAULT_SETTINGS) as Array<keyof typeof DEFAULT_SETTINGS>) {
      if (key in body) {
        const val = parseFloat(String(body[key]));
        if (isNaN(val)) continue;
        const bounds = SETTINGS_BOUNDS[key];
        sanitized[key] = bounds ? Math.min(bounds.max, Math.max(bounds.min, val)) : val;
      }
    }

    const updated = { ...DEFAULT_SETTINGS, ...sanitized };
    await store.setJSON("settings", updated);

    auditLog("SETTINGS_UPDATED", { ip, changes: sanitized });
    return Response.json(updated);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/settings",
  method: ["GET", "POST"],
};
