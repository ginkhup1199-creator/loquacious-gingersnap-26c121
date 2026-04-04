import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import crypto from "node:crypto";

const VALID_KYC_STATES = ["pending", "submitted", "approved", "rejected", "unverified"];
const ADMIN_ONLY_STATES = ["approved", "rejected", "unverified"];

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

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) {
    return Response.json({ error: "Admin token not configured" }, { status: 503 });
  }

  const ip = getClientIp(req, context);

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");
    const key = wallet ? `kyc-${sanitize(wallet, 100).toLowerCase()}` : "kyc";
    const kyc = await store.get(key, { type: "json" });
    return Response.json(kyc || { state: "unverified", name: "", docType: "" });
  }

  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }

    const state = sanitize(body.state as string, 20);
    if (!VALID_KYC_STATES.includes(state)) {
      return Response.json({ error: "Invalid KYC state" }, { status: 400 });
    }

    // Admin-only state transitions
    if (ADMIN_ONLY_STATES.includes(state)) {
      if (!validateAdminToken(req)) {
        auditLog("UNAUTHORIZED_ACCESS", { ip, resource: "kyc/admin-update" });
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }
    }

    const wallet = body.wallet ? sanitize(body.wallet as string, 100).toLowerCase() : null;
    const kycData = {
      state,
      name: sanitize(body.name as string, 200),
      docType: sanitize(body.docType as string, 50),
      updatedAt: new Date().toISOString(),
      ...(wallet && { wallet }),
    };

    const key = wallet ? `kyc-${wallet}` : "kyc";
    await store.setJSON(key, kycData);

    const logAction = state === "approved" ? "USER_KYC_APPROVED"
      : state === "rejected" ? "USER_KYC_REJECTED"
      : "USER_KYC_SUBMITTED";
    auditLog(logAction, { ip, state, wallet });

    return Response.json(kycData);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/kyc",
  method: ["GET", "POST"],
};
