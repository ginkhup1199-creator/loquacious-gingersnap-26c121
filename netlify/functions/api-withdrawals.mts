import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  getClientIp,
} from "../lib/security.js";

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
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
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "process-withdrawal", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      auditLog("ADMIN_WRITE", { operation: "process-withdrawal", withdrawalId: body.id, ip });

      const existing = (await store.get("withdrawals", { type: "json" })) || [];
      const updated = (existing as { id: number }[]).filter(
        (w) => w.id !== body.id
      );
      await store.setJSON("withdrawals", updated);
      return secureJson({ success: true });
    }

    return secureJson({ error: "Invalid action" }, 400);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/withdrawals",
  method: ["GET", "POST"],
};
