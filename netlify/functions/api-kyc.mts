import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  persistAuditLog,
  getClientIp,
} from "../lib/security.js";

const ALLOWED_STATES = ["pending", "approved", "unverified"] as const;

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  // ── GET /api/kyc ──────────────────────────────────────────────────────────
  if (req.method === "GET") {
    const url = new URL(req.url);
    const walletParam = url.searchParams.get("wallet");
    const listMode = url.searchParams.get("list") === "true";

    // Per-wallet lookup (used by user frontend when connected)
    if (walletParam) {
      const safeWallet = sanitizeString(walletParam, 100).toLowerCase();
      const kyc = await store.get(`kyc-${safeWallet}`, { type: "json" });
      return secureJson(kyc || { state: "unverified", name: "", docType: "" }, 200, true);
    }

    // Admin list mode: return all pending submissions
    if (listMode) {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "list-kyc", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }
      const pendingList = ((await store.get("kyc-pending", { type: "json" })) || []) as string[];
      const submissions = await Promise.all(
        pendingList.map((w) => store.get(`kyc-${w}`, { type: "json" }))
      );
      return secureJson(submissions.filter(Boolean), 200);
    }

    // Default: global KYC record (backwards-compatible fallback)
    const kyc = await store.get("kyc", { type: "json" });
    return secureJson(kyc || { state: "unverified", name: "", docType: "" }, 200, true);
  }

  // ── POST /api/kyc ─────────────────────────────────────────────────────────
  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    const state = sanitizeString(String(body.state ?? ""), 20);
    if (!(ALLOWED_STATES as readonly string[]).includes(state)) {
      return secureJson({ error: "Invalid state" }, 400);
    }

    const name    = sanitizeString(String(body.name    ?? ""), 100);
    const docType = sanitizeString(String(body.docType ?? ""), 50);
    const wallet  = sanitizeString(String(body.wallet  ?? ""), 100).toLowerCase();

    // Optional base64-encoded document image — limit to ~2 MB of base64 characters
    const MAX_IMAGE_B64 = 2_800_000; // ~2 MB decoded
    const rawImage = body.documentImage;
    let documentImage: string | null = null;
    if (rawImage && typeof rawImage === "string" && rawImage.length <= MAX_IMAGE_B64) {
      // Accept data URIs with an allowed image MIME type
      const DATA_URI_RE = /^data:image\/(jpeg|png|gif|webp|bmp);base64,[A-Za-z0-9+/]+=*$/;
      if (DATA_URI_RE.test(rawImage)) {
        documentImage = rawImage;
      }
    }

    // Admin-only: approve or reset KYC
    if (state === "approved" || state === "unverified") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "update-kyc", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const kycData = {
        state, name, docType, wallet,
        ...(documentImage && { documentImage }),
        updatedAt: new Date().toISOString(),
      };

      if (wallet) {
        await store.setJSON(`kyc-${wallet}`, kycData);
        // Remove from the pending list regardless of new state
        const pendingList = ((await store.get("kyc-pending", { type: "json" })) || []) as string[];
        const filtered = pendingList.filter((w) => w !== wallet);
        await store.setJSON("kyc-pending", filtered);
      }
      // Also keep the global record updated for backwards compatibility
      await store.setJSON("kyc", kycData);

      await persistAuditLog("ADMIN_WRITE", {
        operation: "update-kyc", state,
        wallet: wallet ? `${wallet.slice(0, 8)}…` : "(none)", ip,
      }, store);

      return secureJson(kycData);
    }

    // User submitting KYC (state === "pending")
    if (!name)    return secureJson({ error: "Name is required for KYC submission" }, 400);
    if (!docType) return secureJson({ error: "Document type is required" }, 400);

    const kycData = {
      state, name, docType, wallet,
      ...(documentImage && { documentImage }),
      submittedAt: new Date().toISOString(),
    };

    if (wallet) {
      await store.setJSON(`kyc-${wallet}`, kycData);
      const pendingList = ((await store.get("kyc-pending", { type: "json" })) || []) as string[];
      if (!pendingList.includes(wallet)) {
        pendingList.push(wallet);
        await store.setJSON("kyc-pending", pendingList);
      }
    }
    // Also keep the global record for backwards compatibility
    await store.setJSON("kyc", kycData);

    return secureJson(kycData);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/kyc",
  method: ["GET", "POST"],
};
