import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  validateAnyAdminSession,
  hasPermission,
  secureJson,
  sanitizeString,
  auditLog,
  persistAuditLog,
  getClientIp,
} from "../lib/security.js";
import { parseJsonObject } from "../lib/validation.js";

const ALLOWED_STATES = ["pending", "approved", "unverified", "rejected"] as const;
const MAX_IMAGE_FIELD_LENGTH = 1_500_000;

function sanitizeImageField(value: unknown): string {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (trimmed.length > MAX_IMAGE_FIELD_LENGTH) return "";
  if (trimmed.startsWith("data:image/")) return trimmed;
  // Allow https hosted image URLs if client uploads to external storage
  if (/^https:\/\//i.test(trimmed)) return sanitizeString(trimmed, 2048);
  return "";
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  // ── GET /api/v2/kyc ───────────────────────────────────────────────────────
  if (req.method === "GET") {
    const url = new URL(req.url);
    const walletParam = url.searchParams.get("wallet");
    const listMode = url.searchParams.get("list") === "true";

    // Per-wallet lookup (used by user frontend when connected)
    if (walletParam) {
      const safeWallet = sanitizeString(walletParam, 100).toLowerCase();
      const kyc = await store.get(`kyc-${safeWallet}`, { type: "json" });
      return secureJson(kyc || { state: "unverified", name: "", docType: "", photoFront: "", photoBack: "" }, 200, true);
    }

    // Admin list mode: return all pending submissions
    if (listMode) {
      const sessionResult = await validateAnyAdminSession(req, store);
      if (!sessionResult.valid || !hasPermission(sessionResult, "kyc")) {
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
    return secureJson(kyc || { state: "unverified", name: "", docType: "", photoFront: "", photoBack: "" }, 200, true);
  }

  // ── POST /api/v2/kyc ──────────────────────────────────────────────────────
  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await parseJsonObject(req);
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
    const photoFront = sanitizeImageField(body.photoFront);
    const photoBack = sanitizeImageField(body.photoBack);

    // Admin-only: approve, reject, or reset KYC
    if (state === "approved" || state === "unverified" || state === "rejected") {
      const sessionResult = await validateAnyAdminSession(req, store);
      if (!sessionResult.valid || !hasPermission(sessionResult, "kyc")) {
        auditLog("AUTH_FAILURE", { operation: "update-kyc", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const existing = wallet
        ? ((await store.get(`kyc-${wallet}`, { type: "json" })) as Record<string, unknown> | null)
        : ((await store.get("kyc", { type: "json" })) as Record<string, unknown> | null);

      const rejectionReason = sanitizeString(String(body.rejectionReason ?? ""), 500);

      const kycData: Record<string, unknown> = {
        state,
        name: name || String(existing?.name || ""),
        docType: docType || String(existing?.docType || ""),
        wallet,
        photoFront: photoFront || String(existing?.photoFront || ""),
        photoBack: photoBack || String(existing?.photoBack || ""),
        updatedAt: new Date().toISOString(),
      };

      if (state === "rejected") {
        kycData.rejectionReason = rejectionReason || "Rejected by admin";
        kycData.rejectedAt = new Date().toISOString();
      }
      if (state === "approved") {
        kycData.approvedAt = new Date().toISOString();
      }

      if (wallet) {
        await store.setJSON(`kyc-${wallet}`, kycData);
        const pendingList = ((await store.get("kyc-pending", { type: "json" })) || []) as string[];
        const filtered = pendingList.filter((w) => w !== wallet);
        await store.setJSON("kyc-pending", filtered);
      }
      await store.setJSON("kyc", kycData);

      await persistAuditLog("ADMIN_WRITE", {
        operation: "update-kyc", state,
        wallet: wallet ? `${wallet.slice(0, 8)}…` : "(none)",
        ...(state === "rejected" ? { rejectionReason } : {}),
        ip,
      }, store);

      return secureJson(kycData);
    }

    // User submitting KYC (state === "pending")
    if (!name)    return secureJson({ error: "Name is required for KYC submission" }, 400);
    if (!docType) return secureJson({ error: "Document type is required" }, 400);
    if (!photoFront || !photoBack) {
      return secureJson({ error: "Both document photos are required" }, 400);
    }

    const kycData = {
      state, name, docType, wallet,
      photoFront,
      photoBack,
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
  path: "/api/v2/kyc",
  method: ["GET", "POST"],
};
