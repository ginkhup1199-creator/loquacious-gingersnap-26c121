import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";

const DEFAULT_SETTINGS = {
  swapFee: 0.5,
  binaryPayout: 85,
  btcStakingApy: 12.5,
};

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });

  if (req.method === "GET") {
    const settings = await store.get("settings", { type: "json" });
    return Response.json(settings || DEFAULT_SETTINGS);
  }

  if (req.method === "POST") {
    const body = await req.json();
    await store.setJSON("settings", body);
    return Response.json(body);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/settings",
  method: ["GET", "POST"],
};
