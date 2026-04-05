import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { createHash, randomBytes, timingSafeEqual } from "crypto";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour
const SESSION_STORE_KEY = "admin-session";

// ---------------------------------------------------------------------------
// Session helpers (inlined here so esbuild bundles each function independently)
// ---------------------------------------------------------------------------

function generateSessionId(): string {
  return randomBytes(32).toString("hex");
}

interface StoredSession {
  sessionId: string;
  expiresAt: string;
  createdAt: string;
  usedAt: string | null;
}

async function createSession(
  store: ReturnType<typeof getStore>
): Promise<{ sessionId: string; expiresAt: string }> {
  const sessionId = generateSessionId();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  const session: StoredSession = {
    sessionId,
    expiresAt,
    createdAt: new Date().toISOString(),
    usedAt: null,
  };
  await store.setJSON(SESSION_STORE_KEY, session);
  return { sessionId, expiresAt };
}

async function destroySession(store: ReturnType<typeof getStore>): Promise<void> {
  await store.delete(SESSION_STORE_KEY);
}

function timingSafeTokenCompare(a: string, b: string): boolean {
  try {
    const maxLen = Math.max(a.length, b.length);
    const bufA = Buffer.alloc(maxLen);
    const bufB = Buffer.alloc(maxLen);
    Buffer.from(a).copy(bufA);
    Buffer.from(b).copy(bufB);
    return a.length === b.length && timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

function getClientIp(context: Context): string {
  return context.ip || "(unknown)";
}

function securityHeaders(): Record<string, string> {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
  };
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const adminToken = process.env.ADMIN_TOKEN;
  const ip = getClientIp(context);
  const headers = securityHeaders();

  if (!adminToken) {
    console.warn(`[AUDIT] {"event":"AUTH_FAILURE","reason":"ADMIN_TOKEN not configured","ip":"${ip}"}`);
    return Response.json({ error: "Admin token not configured" }, { status: 503, headers });
  }

  // POST /api/admin/session  → create a new session
  if (req.method === "POST") {
    const token = req.headers.get("X-Admin-Token");

    if (!token || !timingSafeTokenCompare(token, adminToken)) {
      console.warn(`[AUDIT] {"event":"AUTH_FAILURE","reason":"Invalid admin token","ip":"${ip}"}`);
      return Response.json({ error: "Unauthorized" }, { status: 401, headers });
    }

    const { sessionId, expiresAt } = await createSession(store);

    console.log(`[AUDIT] {"event":"SESSION_CREATED","sessionId":"${sessionId.slice(0, 8)}…","ip":"${ip}"}`);

    return Response.json(
      {
        sessionId,
        expiresAt,
        message: "Session created. Use X-Session-Token header for admin operations.",
      },
      { status: 201, headers }
    );
  }

  // DELETE /api/admin/session  → destroy the current session (logout)
  if (req.method === "DELETE") {
    const sessionId = req.headers.get("X-Session-Token");
    await destroySession(store);
    console.log(`[AUDIT] {"event":"SESSION_DESTROYED","sessionId":"${sessionId ? sessionId.slice(0, 8) + "…" : "(none)"}","ip":"${ip}"}`);
    return Response.json({ message: "Session destroyed" }, { status: 200, headers });
  }

  return new Response("Method not allowed", { status: 405, headers });
};

export const config: Config = {
  path: "/api/admin/session",
  method: ["POST", "DELETE"],
};
