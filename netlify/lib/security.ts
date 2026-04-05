/**
 * Shared security utilities for NexusTrade Netlify Functions.
 *
 * Provides:
 *  - Session token validation (backed by @netlify/blobs)
 *  - Standard security response headers
 *  - LLM prompt-injection detection
 *  - Input sanitization helpers
 *  - Audit logging
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
}

export interface SessionValidationResult {
  valid: boolean;
  reason?: string;
  session?: StoredSession;
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
