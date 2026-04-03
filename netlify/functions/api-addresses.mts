import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";

const DEFAULT_ADDRESSES: Record<string, string> = {
  TRC20: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
  ERC20: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  BSC: "0x55d398326f99059fF775485246999027B3197955",
  SOL: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
  BTC: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
};

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });

  if (req.method === "GET") {
    const addresses = await store.get("deposit-addresses", { type: "json" });
    return Response.json(addresses || DEFAULT_ADDRESSES);
  }

  if (req.method === "POST") {
    const body = await req.json();
    await store.setJSON("deposit-addresses", body);
    return Response.json(body);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/addresses",
  method: ["GET", "POST"],
};
