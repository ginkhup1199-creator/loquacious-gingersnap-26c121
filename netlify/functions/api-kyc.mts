import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });

  if (req.method === "GET") {
    const kyc = await store.get("kyc", { type: "json" });
    return Response.json(
      kyc || { state: "unverified", name: "", docType: "" }
    );
  }

  if (req.method === "POST") {
    const body = await req.json();
    await store.setJSON("kyc", body);
    return Response.json(body);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/kyc",
  method: ["GET", "POST"],
};
