import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });

  if (req.method === "GET") {
    const messages = await store.get("chat-messages", { type: "json" });
    return Response.json(messages || []);
  }

  if (req.method === "POST") {
    const body = await req.json();
    const existing =
      (await store.get("chat-messages", { type: "json" })) || [];
    existing.push({
      sender: body.sender,
      text: body.text,
      time: Date.now(),
    });
    await store.setJSON("chat-messages", existing);
    return Response.json(existing);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/chat",
  method: ["GET", "POST"],
};
