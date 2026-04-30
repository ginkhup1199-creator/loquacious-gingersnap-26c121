import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  getClientIp,
} from "../lib/security.js";

function generate5DigitId(): string {
  return String(Math.floor(10000 + Math.random() * 90000));
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
    const userid = url.searchParams.get("userid");

    if (wallet) {
      // Per-wallet lookup: public (used by user frontend on connect)
      const safeWallet = sanitizeString(String(wallet), 100).toLowerCase();
      if (!safeWallet) {
        return secureJson({ error: "Invalid wallet address" }, 400);
      }
      const user = await store.get(`user-${safeWallet}`, { type: "json" });
      return secureJson(user || null, 200, true);
    }

    if (userid) {
      // UID lookup: admin-only — resolves a 5-digit UID to a user record
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "lookup-userid", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }
      const safeUid = String(userid);
      if (!/^\d{5}$/.test(safeUid)) {
        return secureJson({ error: "Invalid UID — must be exactly 5 digits" }, 400);
      }
      const uidRecord = (await store.get(`userid-${safeUid}`, { type: "json" })) as { wallet: string } | null;
      if (!uidRecord || !uidRecord.wallet) {
        return secureJson({ error: "UID not found" }, 404);
      }
      const safeUidWallet = sanitizeString(String(uidRecord.wallet), 100).toLowerCase();
      if (!safeUidWallet) {
        return secureJson({ error: "Invalid UID record" }, 400);
      }
      const user = await store.get(`user-${safeUidWallet}`, { type: "json" });
      return secureJson(user || { userId: safeUid, wallet: safeUidWallet }, 200, true);
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

    const safeWallet = sanitizeString(String(wallet), 100).toLowerCase();
    if (!safeWallet) {
      return secureJson({ error: "Invalid wallet address" }, 400);
    }

    const existing = await store.get(`user-${safeWallet}`, { type: "json" });
    if (existing) {
      return secureJson(existing, 200, true);
    }

    let userId = generate5DigitId();
    let attempts = 0;
    while (attempts < 50) {
      const taken = await store.get(`userid-${userId}`, { type: "json" });
      if (!taken) break;
      userId = generate5DigitId();
      attempts++;
    }

    const user = {
      userId,
      wallet: safeWallet,
      createdAt: new Date().toISOString(),
    };

    await store.setJSON(`user-${safeWallet}`, user);
    await store.setJSON(`userid-${userId}`, { wallet: safeWallet });

    const allUsers = ((await store.get("all-users", { type: "json" })) as any[] || [])
      .filter((u) => u && typeof u.wallet === "string" && u.wallet.toLowerCase() !== safeWallet);
    allUsers.push(user);
    await store.setJSON("all-users", allUsers);

    return secureJson(user);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/v2/users",
  method: ["GET", "POST"],
};
