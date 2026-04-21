import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { randomInt } from "crypto";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  persistAuditLog,
  getClientIp,
} from "../lib/security.js";

function generate5DigitId(): string {
  return String(randomInt(10000, 100000));
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Service not configured" }, 503);
  }

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");

    if (wallet) {
      // Per-wallet lookup: public (used by user frontend on connect)
      const user = await store.get(`user-${wallet}`, { type: "json" });
      return secureJson(user || null, 200, true);
    }

    // List all users: admin only
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "list-users", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    const allUsers = await store.get("all-users", { type: "json" });
    return secureJson(allUsers || [], 200, true);
  }

  if (req.method === "POST") {
    let body: any;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }
    const { wallet } = body;

    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }

    const safeWallet = sanitizeString(String(wallet), 100);
    if (!safeWallet) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }

    const existing = await store.get(`user-${safeWallet}`, { type: "json" });
    if (existing) {
      return secureJson(existing, 200, true);
    }

    let userId = "";
    for (let attempts = 0; attempts < 100; attempts++) {
      const candidate = generate5DigitId();
      const taken = await store.get(`userid-${candidate}`, { type: "json" });
      if (!taken) {
        userId = candidate;
        break;
      }
    }

    if (!userId) {
      await persistAuditLog("SECURITY_WARNING", { operation: "user-registration-id-collision-exhausted", wallet: `${safeWallet.slice(0, 8)}…`, ip }, store);
      return secureJson({ error: "Unable to allocate user ID. Please retry." }, 503);
    }

    const user = {
      userId,
      wallet: safeWallet,
      createdAt: new Date().toISOString(),
    };

    await store.setJSON(`user-${safeWallet}`, user);
    await store.setJSON(`userid-${userId}`, { wallet: safeWallet });

    const allUsers = (await store.get("all-users", { type: "json" })) as any[] || [];
    allUsers.push(user);
    await store.setJSON("all-users", allUsers);
    await persistAuditLog("USER_WRITE", { operation: "user-registration", wallet: `${safeWallet.slice(0, 8)}…`, userId, ip }, store);

    return secureJson(user);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/users",
  method: ["GET", "POST"],
};
