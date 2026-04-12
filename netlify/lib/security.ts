/**
 * Shared security utilities for NexusTrade Netlify Functions.
 *
 * Provides:
 *  - Session token validation (backed by @netlify/blobs)
 *  - Standard security response headers
 *  - LLM prompt-injection detection
 *  - Input sanitization helpers
 *  - Audit logging
 *  - In-process rate limiting (per-IP, sliding window)
 */

import { getStore } from "@netlify/blobs";
import { timingSafeEqual } from "crypto";
import type { Context } from "@netlify/functions";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StoredSession {
  sessionId: string;
  expiresAt: string;
  createdAt: string;
  usedAt: string | null;
  role?: "master";
}

export interface StoredSubAdminSession {
  sessionId: string;
  username: string;
  permissions: string[];
  expiresAt: string;
  createdAt: string;
}

export interface SessionValidationResult {
  valid: boolean;
  reason?: string;
  session?: StoredSession;
}

export interface AnySessionResult {
  valid: boolean;
  reason?: string;
  role?: "master" | "subadmin";
  permissions?: string[];
  username?: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SESSION_STORE_KEY = "admin-session";

// ---------------------------------------------------------------------------
// Security Headers
// ---------------------------------------------------------------------------

/**
 * Returns standard security response headers.
 * These are applied to every API response.
 */
export function securityHeaders(options: { cache?: boolean } = {}): Record<string, string> {
  const headers: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  };

  if (!options.cache) {
    headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private";
    headers["Pragma"] = "no-cache";
  }

  return headers;
}

/**
 * Creates a JSON response with security headers applied.
 */
export function secureJson(body: unknown, status = 200, cache = false): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...securityHeaders({ cache }),
    },
  });
}

// ---------------------------------------------------------------------------
// Session Validation
// ---------------------------------------------------------------------------

/**
 * Validates the X-Session-Token header against the stored session in Netlify Blobs.
 * The session must exist, not be expired, and the token must match exactly.
 */
export async function validateAdminSession(
  req: Request,
  store: ReturnType<typeof getStore>
): Promise<SessionValidationResult> {
  const sessionId = req.headers.get("X-Session-Token");

  if (!sessionId || typeof sessionId !== "string") {
    return { valid: false, reason: "No session token provided" };
  }

  let session: StoredSession | null = null;
  try {
    session = await store.get(SESSION_STORE_KEY, { type: "json" }) as StoredSession | null;
  } catch {
    return { valid: false, reason: "Session store unavailable" };
  }

  if (!session) {
    return { valid: false, reason: "No active session" };
  }

  // Constant-time comparison to prevent timing attacks
  let tokenMatch = false;
  try {
    const maxLen = Math.max(sessionId.length, session.sessionId.length);
    const bufA = Buffer.alloc(maxLen);
    const bufB = Buffer.alloc(maxLen);
    Buffer.from(sessionId).copy(bufA);
    Buffer.from(session.sessionId).copy(bufB);
    tokenMatch = sessionId.length === session.sessionId.length && timingSafeEqual(bufA, bufB);
  } catch {
    tokenMatch = false;
  }

  if (!tokenMatch) {
    return { valid: false, reason: "Invalid session token" };
  }

  if (new Date(session.expiresAt).getTime() < Date.now()) {
    // Clean up the expired session
    try { await store.delete(SESSION_STORE_KEY); } catch { /* best effort */ }
    return { valid: false, reason: "Session expired" };
  }

  return { valid: true, session };
}

// ---------------------------------------------------------------------------
// Sub-Admin Session Validation
// ---------------------------------------------------------------------------

const SUB_ADMIN_SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour

/**
 * Validates either a master session or a sub-admin session from the
 * X-Session-Token header. Returns role and permissions so callers can enforce
 * permission-based access control.
 */
export async function validateAnyAdminSession(
  req: Request,
  store: ReturnType<typeof getStore>
): Promise<AnySessionResult> {
  const sessionId = req.headers.get("X-Session-Token");
  if (!sessionId || typeof sessionId !== "string") {
    return { valid: false, reason: "No session token provided" };
  }

  // 1. Try master session first
  const masterResult = await validateAdminSession(req, store);
  if (masterResult.valid) {
    return { valid: true, role: "master" };
  }

  // 2. Try sub-admin session stored under its own key
  let subSession: StoredSubAdminSession | null = null;
  try {
    subSession = await store.get(`subadmin-session-${sessionId}`, { type: "json" }) as StoredSubAdminSession | null;
  } catch {
    return { valid: false, reason: "Session store unavailable" };
  }

  if (!subSession) {
    return { valid: false, reason: "Invalid session token" };
  }

  // Constant-time token comparison
  let tokenMatch = false;
  try {
    const maxLen = Math.max(sessionId.length, subSession.sessionId.length);
    const bufA = Buffer.alloc(maxLen);
    const bufB = Buffer.alloc(maxLen);
    Buffer.from(sessionId).copy(bufA);
    Buffer.from(subSession.sessionId).copy(bufB);
    tokenMatch = sessionId.length === subSession.sessionId.length && timingSafeEqual(bufA, bufB);
  } catch {
    tokenMatch = false;
  }

  if (!tokenMatch) {
    return { valid: false, reason: "Invalid session token" };
  }

  if (new Date(subSession.expiresAt).getTime() < Date.now()) {
    try { await store.delete(`subadmin-session-${sessionId}`); } catch { /* best effort */ }
    return { valid: false, reason: "Session expired" };
  }

  return {
    valid: true,
    role: "subadmin",
    username: subSession.username,
    permissions: subSession.permissions,
  };
}

/**
 * Returns true if the session has the given permission.
 * Master sessions always have every permission.
 */
export function hasPermission(result: AnySessionResult, permission: string): boolean {
  if (result.role === "master") return true;
  return (result.permissions ?? []).includes(permission);
}

// ---------------------------------------------------------------------------
// LLM Injection Detection
// ---------------------------------------------------------------------------

const INJECTION_PATTERNS: RegExp[] = [
  /\bignore\s+(all\s+)?previous\s+instructions?\b/i,
  /\bforget\s+(all\s+)?previous\s+instructions?\b/i,
  /\bdisregard\s+(all\s+)?previous\s+instructions?\b/i,
  /\boverride\s+(system\s+)?prompt\b/i,
  /\bnew\s+instructions?:/i,
  /\bsystem\s*:\s*you\s+are\b/i,
  /\byou\s+are\s+now\b.{0,60}\bassistant\b/i,
  /\bact\s+as\b.{0,40}\b(admin|root|system|superuser)\b/i,
  /\bdan\s+mode\b/i,
  /\bjailbreak\b/i,
  /\bdev\s+mode\b/i,
  /\bpretend\s+you\s+(have\s+no|don'?t\s+have)\s+(restrictions?|limitations?|rules?)\b/i,
  /\byou\s+(have\s+no|don'?t\s+have)\s+(restrictions?|limitations?|rules?)\b/i,
  /\bprint\s+(your\s+)?(system\s+)?prompt\b/i,
  /\brepeat\s+(your\s+)?initial\s+instructions?\b/i,
  /\bshow\s+(me\s+)?(your\s+)?(secret|api[_\s]?key|token|password|credential|env)\b/i,
  /\bwhat\s+(is|are)\s+(your\s+)?(api[_\s]?key|token|secret|password|admin)\b/i,
  /process\.env/i,
  /ADMIN_TOKEN/i,
  /\.env\b/i,
  /\bcall\s+(function|tool)\s*\(/i,
  /\bexecute\s+(command|script|code|function)\b/i,
  /\brun\s+(shell|bash|cmd|powershell|python|node)\b/i,
  /\beval\s*\(/i,
  /------+\s*system\s*------+/i,
  /###\s*system\s*###/i,
  /\[system\]/i,
  /<\s*system\s*>/i,
];

/**
 * Checks user input for LLM prompt-injection patterns.
 * Returns { safe: false } if an injection pattern is detected.
 */
export function checkLLMInput(input: string): { safe: boolean; reason?: string } {
  if (typeof input !== "string") return { safe: false, reason: "Input must be a string" };
  if (input.trim().length === 0) return { safe: true };
  if (input.length > 4000) return { safe: false, reason: "Message exceeds maximum length" };

  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(input)) {
      return { safe: false, reason: "Message contains a disallowed pattern" };
    }
  }

  return { safe: true };
}

// ---------------------------------------------------------------------------
// Content Sanitization
// ---------------------------------------------------------------------------

/**
 * Sanitizes a string value: removes null bytes, trims whitespace,
 * enforces max length, and escapes HTML special characters.
 */
export function sanitizeString(value: unknown, maxLength = 1000): string {
  if (typeof value !== "string") return String(value ?? "");
  // eslint-disable-next-line no-control-regex
  let s = value.replace(/\x00/g, "").trim();
  if (s.length > maxLength) s = s.slice(0, maxLength);
  if (/^(javascript|data|vbscript|file):/i.test(s)) return "";
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

// ---------------------------------------------------------------------------
// Audit Logging
// ---------------------------------------------------------------------------

export function getClientIp(context: Context): string {
  return context.ip || "(unknown)";
}

export function auditLog(event: string, details: Record<string, unknown> = {}): void {
  // Scrub sensitive fields before logging
  const safe = { ...details };
  delete safe["token"];
  delete safe["adminToken"];
  delete safe["password"];
  delete safe["secret"];
  delete safe["sessionId"]; // always mask full session IDs

  if (details["sessionId"] && typeof details["sessionId"] === "string") {
    safe["sessionIdPrefix"] = (details["sessionId"] as string).slice(0, 8) + "…";
  }

  console.log(`[AUDIT] ${JSON.stringify({ timestamp: new Date().toISOString(), event, ...safe })}`);
}

// ---------------------------------------------------------------------------
// Persistent Audit Logging
// ---------------------------------------------------------------------------

interface AuditEntry {
  timestamp: string;
  event: string;
  [key: string]: unknown;
}

const MAX_AUDIT_LOG_ENTRIES = 500;

/**
 * Logs an audit event to console AND persists it to @netlify/blobs.
 * Maintains a rolling window of the last MAX_AUDIT_LOG_ENTRIES entries
 * (newest first). When the limit is exceeded, the oldest entries are dropped.
 * Non-fatal: persistence failures do not interrupt the request.
 */
export async function persistAuditLog(
  event: string,
  details: Record<string, unknown> = {},
  store: ReturnType<typeof getStore>
): Promise<void> {
  auditLog(event, details);

  const safe: Record<string, unknown> = { ...details };
  delete safe["token"];
  delete safe["adminToken"];
  delete safe["password"];
  delete safe["secret"];
  delete safe["sessionId"];

  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    event,
    ...safe,
  };

  try {
    const existing = ((await store.get("audit-log", { type: "json" })) ?? []) as AuditEntry[];
    existing.unshift(entry);
    if (existing.length > MAX_AUDIT_LOG_ENTRIES) existing.splice(MAX_AUDIT_LOG_ENTRIES);
    await store.setJSON("audit-log", existing);
  } catch {
    // Non-fatal: persist failure must never break the operation
  }
}

// ---------------------------------------------------------------------------
// In-Process Rate Limiting (sliding window, per IP)
// ---------------------------------------------------------------------------

interface RateLimitBucket {
  timestamps: number[];
}

// Module-level map — persists across warm-Lambda invocations in the same
// process.  Netlify Functions are ephemeral, so this provides a best-effort
// per-process guard.  For stricter enforcement, use Netlify Edge Functions or
// a WAF layer in front of the site.
const _rateLimitBuckets = new Map<string, RateLimitBucket>();

const RATE_LIMIT_MAX_DEFAULT     = 30;
const RATE_LIMIT_WINDOW_DEFAULT  = 60_000; // 1 minute

/**
 * Checks whether the given key (typically a client IP address) has exceeded
 * the rate limit.  Returns `{ allowed: true }` when the request may proceed,
 * or `{ allowed: false, retryAfterMs }` when the caller is rate-limited.
 *
 * Limits are configurable via environment variables:
 *   RATE_LIMIT_MAX         – max requests per window (default 30)
 *   RATE_LIMIT_WINDOW_MS   – window duration in ms   (default 60000)
 */
export function checkRateLimit(key: string): { allowed: boolean; retryAfterMs?: number } {
  const max    = parseInt(process.env.RATE_LIMIT_MAX        ?? String(RATE_LIMIT_MAX_DEFAULT),    10);
  const window = parseInt(process.env.RATE_LIMIT_WINDOW_MS  ?? String(RATE_LIMIT_WINDOW_DEFAULT), 10);

  const now    = Date.now();
  const cutoff = now - window;

  let bucket = _rateLimitBuckets.get(key);
  if (!bucket) {
    bucket = { timestamps: [] };
    _rateLimitBuckets.set(key, bucket);
  }

  // Evict old timestamps outside the current window
  bucket.timestamps = bucket.timestamps.filter(ts => ts > cutoff);

  if (bucket.timestamps.length >= max) {
    // Oldest timestamp in the window tells us when a slot will free up.
    // Guard against clock skew: retryAfterMs is always at least 0.
    const oldest       = bucket.timestamps[0];
    const retryAfterMs = oldest <= now ? oldest + window - now : window;
    return { allowed: false, retryAfterMs: Math.max(0, retryAfterMs) };
  }

  bucket.timestamps.push(now);
  return { allowed: true };
}

/**
 * Returns a 429 JSON response carrying a Retry-After header.
 */
export function rateLimitExceededResponse(retryAfterMs = RATE_LIMIT_WINDOW_DEFAULT): Response {
  const retryAfterSec = Math.ceil(retryAfterMs / 1000);
  return new Response(
    JSON.stringify({ error: "Too many requests. Please try again later." }),
    {
      status: 429,
      headers: {
        "Content-Type": "application/json",
        "Retry-After": String(retryAfterSec),
        ...securityHeaders(),
      },
    }
  );
}
