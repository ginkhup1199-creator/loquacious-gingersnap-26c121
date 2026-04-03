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

  if (req.method === "GET") {
    const features = await store.get("features", { type: "json" });
    return Response.json(features || DEFAULTS);
  }

  if (req.method === "POST") {
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
