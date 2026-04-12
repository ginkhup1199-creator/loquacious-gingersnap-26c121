import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAnyAdminSession,
  hasPermission,
  secureJson,
  checkLLMInput,
  sanitizeString,
  auditLog,
  getClientIp,
} from "../lib/security.js";

const MAX_CHAT_MESSAGES = 200;

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (req.method === "GET") {
    const messages = await store.get("chat-messages", { type: "json" });
    return secureJson(messages || [], 200, true);
  }

  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    // Sender is determined server-side from session validity; never trusted from client.
    const sessionResult = await validateAnyAdminSession(req, store);
    const sender = (sessionResult.valid && hasPermission(sessionResult, "chat")) ? "admin" : "user";

    const rawText = String(body.text ?? "");

    // Check for LLM prompt-injection patterns
    const llmCheck = checkLLMInput(rawText);
    if (!llmCheck.safe) {
      auditLog("INJECTION_BLOCKED", { reason: llmCheck.reason, ip });
      return secureJson({ error: "Message contains disallowed content" }, 400);
    }

    // Sanitize the message text
    const text = sanitizeString(rawText, 2000);
    if (!text) {
      return secureJson({ error: "Message text is required" }, 400);
    }

    const existing = ((await store.get("chat-messages", { type: "json" })) || []) as unknown[];
    existing.push({ sender, text, time: Date.now() });
    // Keep last 200 messages to prevent unbounded growth
    if (existing.length > MAX_CHAT_MESSAGES) existing.splice(0, existing.length - MAX_CHAT_MESSAGES);
    await store.setJSON("chat-messages", existing);
    return secureJson(existing);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/chat",
  method: ["GET", "POST"],
};
