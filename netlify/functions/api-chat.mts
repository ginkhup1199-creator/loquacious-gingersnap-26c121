import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  secureJson,
  checkLLMInput,
  sanitizeString,
  auditLog,
  getClientIp,
} from "../lib/security.js";

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (req.method === "GET") {
    const messages = await store.get("chat-messages", { type: "json" });
    return secureJson(messages || [], 200, true);
  }

  if (req.method === "POST") {
    const body = await req.json();

    // Sanitize sender name
    const sender = sanitizeString(String(body.sender ?? ""), 64);
    const rawText = String(body.text ?? "");

    // Check for LLM prompt-injection patterns
    const llmCheck = checkLLMInput(rawText);
    if (!llmCheck.safe) {
      auditLog("INJECTION_BLOCKED", { reason: llmCheck.reason, ip });
      return secureJson({ error: "Message contains disallowed content" }, 400);
    }

    // Sanitize the message text
    const text = sanitizeString(rawText, 2000);

    if (!sender || !text) {
      return secureJson({ error: "Sender and text are required" }, 400);
    }

    const existing =
      (await store.get("chat-messages", { type: "json" })) || [];
    (existing as unknown[]).push({
      sender,
      text,
      time: Date.now(),
    });
    await store.setJSON("chat-messages", existing);
    return secureJson(existing);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/chat",
  method: ["GET", "POST"],
};
