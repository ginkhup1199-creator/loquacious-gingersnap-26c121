import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import crypto from "node:crypto";

// In-memory session store per function instance (resets on cold start)
// For production with multiple instances, use a persistent store.
interface Session {
  enterpriseId: string;
  createdAt: number;
  expiresAt: number;
  oneTimeToken: string | null;
  tokenExpiresAt: number;
  tokenUsed: boolean;
}

const activeSessions = new Map<string, Session>();
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes
const TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes

function generateSecureToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("hex");
}

function cleanExpiredSessions(): void {
  const now = Date.now();
  for (const [id, session] of activeSessions.entries()) {
    if (now > session.expiresAt) activeSessions.delete(id);
  }
}

function hashForLog(token: string): string {
  if (!token) return "null";
  return token.slice(0, 4) + "***[" + token.length + "]";
}

function auditLog(action: string, details: Record<string, unknown>): void {
  console.log(`[AUDIT] ${JSON.stringify({ timestamp: new Date().toISOString(), action, ...details })}`);
}

function getClientIp(req: Request, context: Context): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-nf-client-connection-ip") ||
    context.ip ||
    "unknown";
}

// In-memory rate limiter per IP
const rateLimitMap = new Map<string, { count: number; windowStart: number }>();
const RATE_LIMIT_MAX = 20;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  // Clean stale entries
  for (const [k, v] of rateLimitMap.entries()) {
    if (now - v.windowStart > RATE_LIMIT_WINDOW_MS) rateLimitMap.delete(k);
  }
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT_MAX;
}

export default async (req: Request, context: Context) => {
  cleanExpiredSessions();

  const ip = getClientIp(req, context);

  if (isRateLimited(ip)) {
    auditLog("RATE_LIMIT_EXCEEDED", { ip, path: "/api/admin" });
    return Response.json({ error: "Too many requests. Please try again later." }, { status: 429 });
  }

  const adminToken = process.env.ADMIN_TOKEN;
  const enterpriseSecret = process.env.ENTERPRISE_SECRET || adminToken;

  if (!adminToken || !enterpriseSecret) {
    return Response.json({ error: "Admin token not configured" }, { status: 503 });
  }

  // Log a warning if ENTERPRISE_SECRET is not separately configured
  if (!process.env.ENTERPRISE_SECRET) {
    console.warn("[SECURITY] ENTERPRISE_SECRET not set - falling back to ADMIN_TOKEN for session auth. Set ENTERPRISE_SECRET for defense-in-depth.");
  }

  const url = new URL(req.url);
  const action = url.searchParams.get("action") || "";

  // ─── POST /api/admin?action=login ─────────────────────────────────────────
  // Authenticates with enterprise credential and creates a session
  if (req.method === "POST" && action === "login") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }

    const providedToken = body.token as string;
    if (!providedToken || typeof providedToken !== "string") {
      auditLog("ADMIN_LOGIN_FAILED", { ip, reason: "No token provided" });
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    // Constant-time comparison against enterprise secret
    let match = false;
    try {
      const a = Buffer.from(providedToken);
      const b = Buffer.from(enterpriseSecret);
      match = a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch {
      match = false;
    }

    if (!match) {
      auditLog("ADMIN_LOGIN_FAILED", { ip, tokenHint: hashForLog(providedToken) });
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    const sessionId = generateSecureToken(24);
    const now = Date.now();
    activeSessions.set(sessionId, {
      enterpriseId: "admin",
      createdAt: now,
      expiresAt: now + SESSION_TTL_MS,
      oneTimeToken: null,
      tokenExpiresAt: 0,
      tokenUsed: true,
    });

    auditLog("ADMIN_SESSION_CREATED", { ip, sessionHint: hashForLog(sessionId) });
    return Response.json({
      sessionId,
      expiresAt: new Date(now + SESSION_TTL_MS).toISOString(),
    });
  }

  // ─── POST /api/admin?action=issue-token ───────────────────────────────────
  // Issues a new one-time token for the current session
  if (req.method === "POST" && action === "issue-token") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }

    const sessionId = body.sessionId as string;
    if (!sessionId) {
      return Response.json({ error: "Session ID required" }, { status: 400 });
    }

    const session = activeSessions.get(sessionId);
    if (!session || Date.now() > session.expiresAt) {
      if (session) activeSessions.delete(sessionId);
      auditLog("ADMIN_TOKEN_INVALID", { ip, reason: "Session not found or expired" });
      return Response.json({ error: "Invalid or expired session" }, { status: 401 });
    }

    // Issue new one-time token (invalidates any previous unused token)
    const rawToken = generateSecureToken(32);
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const tokenExpiresAt = Date.now() + TOKEN_TTL_MS;

    session.oneTimeToken = tokenHash;
    session.tokenExpiresAt = tokenExpiresAt;
    session.tokenUsed = false;

    auditLog("ADMIN_TOKEN_CREATED", { ip, sessionHint: hashForLog(sessionId) });
    return Response.json({
      token: rawToken, // Returned once - never stored in plaintext
      expiresAt: new Date(tokenExpiresAt).toISOString(),
    });
  }

  // ─── POST /api/admin?action=logout ────────────────────────────────────────
  if (req.method === "POST" && action === "logout") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400 });
    }
    const sessionId = body.sessionId as string;
    if (sessionId) {
      activeSessions.delete(sessionId);
      auditLog("ADMIN_SESSION_EXPIRED", { ip, sessionHint: hashForLog(sessionId) });
    }
    return Response.json({ success: true });
  }

  // ─── GET /api/admin?action=stats ─────────────────────────────────────────
  // Returns system statistics. Requires valid session.
  if (req.method === "GET" && action === "stats") {
    const sessionId = req.headers.get("X-Session-Id") || url.searchParams.get("sessionId") || "";
    const session = sessionId ? activeSessions.get(sessionId) : null;

    if (!session || Date.now() > session.expiresAt) {
      auditLog("UNAUTHORIZED_ACCESS", { ip, resource: "admin/stats" });
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    const store = getStore({ name: "app-data", consistency: "strong" });
    const [allUsers, withdrawals] = await Promise.all([
      store.get("all-users", { type: "json" }) as Promise<unknown[]>,
      store.get("withdrawals", { type: "json" }) as Promise<unknown[]>,
    ]);

    return Response.json({
      activeSessions: activeSessions.size,
      registeredUsers: (allUsers || []).length,
      pendingWithdrawals: ((withdrawals || []) as Array<{ status: string }>)
        .filter((w) => w.status === "Pending").length,
      timestamp: new Date().toISOString(),
    });
  }

  // ─── GET /api/admin?action=validate-session ───────────────────────────────
  if (req.method === "GET" && action === "validate-session") {
    const sessionId = url.searchParams.get("sessionId") || "";
    const session = sessionId ? activeSessions.get(sessionId) : null;
    const now = Date.now();

    if (!session || now > session.expiresAt) {
      return Response.json({ valid: false });
    }

    return Response.json({
      valid: true,
      expiresAt: new Date(session.expiresAt).toISOString(),
    });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/admin",
  method: ["GET", "POST"],
};
