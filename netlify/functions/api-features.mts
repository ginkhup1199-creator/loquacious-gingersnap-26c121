import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";

const DEFAULTS = {
  fiat: true,
  send: true,
  swap: true,
  trade: true,
  binary: true,
  ai: true,
  earn: true,
};

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const adminToken = process.env.ADMIN_TOKEN;
  if (!adminToken) {
    return Response.json({ error: "Admin token not configured" }, { status: 503 });
  }

  if (req.method === "GET") {
    const features = await store.get("features", { type: "json" });
    return Response.json(features || DEFAULTS);
  }

  if (req.method === "POST") {
    const token = req.headers.get("X-Admin-Token");
    if (token !== adminToken) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }
    const body = await req.json();
    await store.setJSON("features", body);
    return Response.json(body);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/features",
  method: ["GET", "POST"],
};
