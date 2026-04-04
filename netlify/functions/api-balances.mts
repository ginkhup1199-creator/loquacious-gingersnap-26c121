import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const adminToken = process.env.ADMIN_TOKEN || "admin123";

  if (req.method === "GET") {
    const url = new URL(req.url);
    const wallet = url.searchParams.get("wallet");
    if (!wallet) {
      return Response.json({ error: "Wallet address required" }, { status: 400 });
    }
    const balance = await store.get(`balance-${wallet.toLowerCase()}`, { type: "json" });
    return Response.json(balance || { usdt: 0 });
  }

  if (req.method === "POST") {
    const token = req.headers.get("X-Admin-Token");
    if (token !== adminToken) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }
    const body = await req.json();
    const { wallet, usdt } = body;
    if (!wallet) {
      return Response.json({ error: "Wallet address required" }, { status: 400 });
    }
    const balance = { usdt: parseFloat(usdt) || 0 };
    await store.setJSON(`balance-${wallet.toLowerCase()}`, balance);
    return Response.json(balance);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/balances",
  method: ["GET", "POST"],
};
