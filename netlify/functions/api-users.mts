import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { secureJson, sanitizeString } from "../lib/security.mjs";

function generate5DigitId(): string {
  return String(Math.floor(10000 + Math.random() * 90000));
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");

    if (wallet) {
      const user = await store.get(`user-${wallet}`, { type: "json" });
      return secureJson(user || null, 200, true);
    }

    const allUsers = await store.get("all-users", { type: "json" });
    return secureJson(allUsers || [], 200, true);
  }

  if (req.method === "POST") {
    const body = await req.json() as Record<string, unknown>;
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

    const allUsers = (await store.get("all-users", { type: "json" })) as any[] || [];
    allUsers.push(user);
    await store.setJSON("all-users", allUsers);

    return secureJson(user);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/users",
  method: ["GET", "POST"],
};
