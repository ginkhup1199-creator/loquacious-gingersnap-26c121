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

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const url = new URL(req.url);
    const walletParam = url.searchParams.get("wallet");

    if (walletParam) {
      // Return only this user's withdrawals (no auth needed for own wallet)
      const safeWallet = sanitizeString(walletParam, 100).toLowerCase();
      const all = ((await store.get("withdrawals", { type: "json" })) || []) as Array<{ wallet?: string }>;
      const filtered = all.filter((w) => w.wallet === safeWallet);
      return secureJson(filtered, 200, true);
    }

    // No wallet param: admin view (requires session)
    const sessionResult = await validateAnyAdminSession(req, store);
    if (!sessionResult.valid || !hasPermission(sessionResult, "withdrawals")) {
      auditLog("AUTH_FAILURE", { operation: "list-withdrawals", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }
    const withdrawals = await store.get("withdrawals", { type: "json" });
    return secureJson(withdrawals || [], 200, true);
  }

  if (req.method === "POST") {
    const body = await req.json();
    const { action } = body;

    if (action === "add") {
      const existing = (await store.get("withdrawals", { type: "json" })) || [];
      const newWithdrawal = {
        id: Date.now(),
        wallet: sanitizeString(String(body.wallet ?? ""), 100).toLowerCase(),
        coin: sanitizeString(String(body.coin ?? ""), 20),
        network: sanitizeString(String(body.network ?? ""), 20),
        address: sanitizeString(String(body.address ?? ""), 200),
        amount: parseFloat(body.amount) || 0,
        date: new Date().toISOString().split("T")[0],
        status: "Pending",
      };
      (existing as unknown[]).push(newWithdrawal);
      await store.setJSON("withdrawals", existing);
      return secureJson(newWithdrawal);
    }

    if (action === "process") {
      const sessionResult = await validateAnyAdminSession(req, store);
      if (!sessionResult.valid || !hasPermission(sessionResult, "withdrawals")) {
        auditLog("AUTH_FAILURE", { operation: "process-withdrawal", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const newStatus = sanitizeString(String(body.status ?? "Completed"), 20);
      const allowedStatuses = ["Completed", "Rejected"];
      const safeStatus = allowedStatuses.includes(newStatus) ? newStatus : "Completed";

      await persistAuditLog("ADMIN_WRITE", { operation: "process-withdrawal", withdrawalId: body.id, status: safeStatus, ip }, store);

      const existing = (await store.get("withdrawals", { type: "json" })) || [];
      const updated = (existing as { id: number; status: string }[]).map(
        (w) => w.id === Number(body.id) ? { ...w, status: safeStatus } : w
      );
      await store.setJSON("withdrawals", updated);
      return secureJson({ success: true, status: safeStatus });
    }

    return secureJson({ error: "Invalid action" }, 400);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/withdrawals",
  method: ["GET", "POST"],
};
