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
  checkRateLimit,
  rateLimitExceededResponse,
} from "../lib/security.js";
import { parseJsonObject } from "../lib/validation.js";

const MAX_CHAT_MESSAGES = 200;

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);
  const url = new URL(req.url);

  if (req.method === "GET") {
    const uid = url.searchParams.get("uid");
    const listAll = url.searchParams.get("list");

    if (listAll === "true") {
      const sessionResult = await validateAnyAdminSession(req, store);
      if (!sessionResult.valid || !hasPermission(sessionResult, "chat")) {
        return secureJson({ error: "Unauthorized" }, 403);
      }
      const index = (await store.get("chat-uid-index", { type: "json" })) as Record<string, { lastMessage: number; unread: number }> | null;
      return secureJson(index || {}, 200, true);
    }

    if (uid) {
      const safeUid = sanitizeString(uid, 10);
      if (!safeUid || !/^\d{5}$/.test(safeUid)) {
        return secureJson({ error: "Invalid UID" }, 400);
      }
      const messages = await store.get(`chat-uid-${safeUid}`, { type: "json" });
      return secureJson(messages || [], 200, true);
    }

    // Legacy: return all messages (backward compat)
    const messages = await store.get("chat-messages", { type: "json" });
    return secureJson(messages || [], 200, true);
  }

  if (req.method === "POST") {
    const rl = checkRateLimit(`chat-post:${ip}`);
    if (!rl.allowed) {
      return rateLimitExceededResponse(rl.retryAfterMs);
    }

    let body: Record<string, unknown>;
    try {
      body = await parseJsonObject(req);
    } catch {
      return secureJson({ error: "Invalid JSON" }, 400);
    }

    const sessionResult = await validateAnyAdminSession(req, store);
    const sender = (sessionResult.valid && hasPermission(sessionResult, "chat")) ? "admin" : "user";

    const rawText = String(body.text ?? "");
    const rawUid = String(body.uid ?? "");

    const llmCheck = checkLLMInput(rawText);
    if (!llmCheck.safe) {
      auditLog("INJECTION_BLOCKED", { reason: llmCheck.reason, ip });
      return secureJson({ error: "Message contains disallowed content" }, 400);
    }

    const text = sanitizeString(rawText, 2000);
    if (!text) {
      return secureJson({ error: "Message text is required" }, 400);
    }

    const uid = sanitizeString(rawUid, 10);
    if (!uid || !/^\d{5}$/.test(uid)) {
      return secureJson({ error: "Valid UID is required" }, 400);
    }

    const storeKey = `chat-uid-${uid}`;
    const existing = ((await store.get(storeKey, { type: "json" })) || []) as unknown[];
    existing.push({ sender, text, time: Date.now() });
    if (existing.length > MAX_CHAT_MESSAGES) existing.splice(0, existing.length - MAX_CHAT_MESSAGES);
    await store.setJSON(storeKey, existing);

    const index = ((await store.get("chat-uid-index", { type: "json" })) || {}) as Record<string, { lastMessage: number; unread: number }>;
    const prev = index[uid] || { lastMessage: 0, unread: 0 };
    index[uid] = {
      lastMessage: Date.now(),
      unread: sender === "user" ? prev.unread + 1 : 0,
    };
    await store.setJSON("chat-uid-index", index);

    // Also write to legacy key for backward compat
    const legacy = ((await store.get("chat-messages", { type: "json" })) || []) as unknown[];
    legacy.push({ sender, text, time: Date.now(), uid });
    if (legacy.length > MAX_CHAT_MESSAGES) legacy.splice(0, legacy.length - MAX_CHAT_MESSAGES);
    await store.setJSON("chat-messages", legacy);

    return secureJson(existing);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/v2/chat",
  method: ["GET", "POST"],
};
