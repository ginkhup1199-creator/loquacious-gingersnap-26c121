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
    const { sender, text } = body;

    if (!sender || typeof sender !== "string" || sender.trim().length === 0) {
      return Response.json({ error: "sender is required" }, { status: 400 });
    }
    if (!text || typeof text !== "string" || text.trim().length === 0) {
      return Response.json({ error: "text is required" }, { status: 400 });
    }
    if (text.length > 2000) {
      return Response.json({ error: "text exceeds maximum length of 2000 characters" }, { status: 400 });
    }

    const existing =
      (await store.get("chat-messages", { type: "json" })) || [];
    existing.push({
      sender: sender.trim().slice(0, 64),
      text: text.trim(),
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
