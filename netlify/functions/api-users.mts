import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";

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
      return Response.json(user || null);
    }

    const allUsers = await store.get("all-users", { type: "json" });
    return Response.json(allUsers || []);
  }

  if (req.method === "POST") {
    const body = await req.json();
    const { wallet } = body;

    if (!wallet) {
      return Response.json({ error: "Wallet address required" }, { status: 400 });
    }

    const existing = await store.get(`user-${wallet}`, { type: "json" });
    if (existing) {
      return Response.json(existing);
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
      wallet,
      createdAt: new Date().toISOString(),
    };

    await store.setJSON(`user-${wallet}`, user);
    await store.setJSON(`userid-${userId}`, { wallet });

    const allUsers = (await store.get("all-users", { type: "json" })) as any[] || [];
    allUsers.push(user);
    await store.setJSON("all-users", allUsers);

    return Response.json(user);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/users",
  method: ["GET", "POST"],
};
