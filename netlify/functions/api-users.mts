import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  getClientIp,
} from "../lib/security.js";
import { normalizeWallet, parseJsonObject, sanitizeWalletLegacy, toArray } from "../lib/validation.js";

type AppUser = {
  userId: string;
  wallet: string;
  createdAt: string;
};

function loadUsers(value: unknown): AppUser[] {
  return toArray<AppUser>(value);
}

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

    if (wallet) {
      // Per-wallet lookup: public (used by user frontend on connect)
      const walletKey = normalizeWallet(String(wallet));
      if (!walletKey) {
        return secureJson({ error: "Invalid wallet address" }, 400);
      }
      // Legacy fallback preserves access to users created before normalization.
      const [normalizedUser, legacyUser] = await Promise.all([
        store.get(`user-${walletKey}`, { type: "json" }),
        store.get(`user-${sanitizeWalletLegacy(wallet)}`, { type: "json" }),
      ]);
      const user = normalizedUser || legacyUser;
      return secureJson(user || null, 200, true);
    }

    // List all users: admin only
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "list-users", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    const allUsers = loadUsers(await store.get("all-users", { type: "json" }));
    return secureJson(allUsers, 200, true);
  }

  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await parseJsonObject(req);
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }
    const wallet = body.wallet;

    if (!wallet) {
      return secureJson({ error: "Wallet address required" }, 400);
    }

    const safeWallet = normalizeWallet(String(wallet));
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

    const user: AppUser = {
      userId,
      wallet: safeWallet,
      createdAt: new Date().toISOString(),
    };

    await store.setJSON(`user-${safeWallet}`, user);
    await store.setJSON(`userid-${userId}`, { wallet: safeWallet });

    const allUsers = loadUsers(await store.get("all-users", { type: "json" }));
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
