import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });

  if (req.method === "GET") {
    const withdrawals = await store.get("withdrawals", { type: "json" });
    return Response.json(withdrawals || []);
  }

  if (req.method === "POST") {
    const body = await req.json();
    const { action } = body;

    if (action === "add") {
      const existing = (await store.get("withdrawals", { type: "json" })) || [];
      const newWithdrawal = {
        id: Date.now(),
        coin: body.coin,
        network: body.network,
        address: body.address,
        amount: body.amount,
        date: new Date().toISOString().split("T")[0],
        status: "Pending",
      };
      existing.push(newWithdrawal);
      await store.setJSON("withdrawals", existing);
      return Response.json(newWithdrawal);
    }

    if (action === "process") {
      const existing = (await store.get("withdrawals", { type: "json" })) || [];
      const updated = existing.filter(
        (w: { id: number }) => w.id !== body.id
      );
      await store.setJSON("withdrawals", updated);
      return Response.json({ success: true });
    }

    return Response.json({ error: "Invalid action" }, { status: 400 });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/withdrawals",
  method: ["GET", "POST"],
};
