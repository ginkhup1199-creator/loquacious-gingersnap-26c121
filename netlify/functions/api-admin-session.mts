import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { createHash, randomBytes, randomInt, timingSafeEqual } from "crypto";
// Note: randomBytes retained for generateSessionId
import nodemailer from "nodemailer";
import {
  checkRateLimit,
  rateLimitExceededResponse,
  validateAdminSession,
  revokeSession,
  revokeAllSessions,
  persistAuditLog,
} from "../lib/security.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SESSION_TTL_MS       = 60 * 60 * 1000;  // 1 hour
const OTP_TTL_MS           = 10 * 60 * 1000;  // 10 minutes
const OTP_MAX_ATTEMPTS     = 5;               // max wrong guesses before OTP is invalidated
const SESSION_STORE_KEY    = "admin-session";
const OTP_STORE_KEY        = "admin-otp";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface StoredSession {
  sessionId: string;
  expiresAt: string;
  createdAt: string;
  usedAt: string | null;
  role?: "master";
}

interface StoredOtp {
  hash: string;       // SHA-256 of the 6-digit code
  expiresAt: string;
  createdAt: string;
  email: string;
  attempts: number;
}



// ---------------------------------------------------------------------------
// Helpers (inlined so esbuild bundles independently)
// ---------------------------------------------------------------------------

function generateSessionId(): string {
  return randomBytes(32).toString("hex");
}

function generateOtp(): string {
  // Use randomInt for an unbiased 6-digit code (inclusive 100000..999999)
  return String(randomInt(100000, 1000000));
}

function hashOtp(otp: string): string {
  return createHash("sha256").update(otp).digest("hex");
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
    role: "master",
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

async function sendOtpEmail(
  adminEmail: string,
  otp: string,
  gmailUser: string,
  gmailAppPassword: string
): Promise<void> {
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: { user: gmailUser, pass: gmailAppPassword },
  });

  await transporter.sendMail({
    from: `"NexusTrade Admin" <${gmailUser}>`,
    to: adminEmail,
    subject: "Your NexusTrade Admin Login Code",
    text: `Your one-time login code is: ${otp}\n\nThis code expires in 10 minutes. Do not share it with anyone.`,
    html: `
      <div style="font-family:sans-serif;max-width:420px;margin:0 auto;background:#0a1325;color:#e2e8f0;padding:32px;border-radius:12px;border:1px solid #1a2642;">
        <h2 style="color:#00f0ff;margin-top:0;">NexusTrade Admin Access</h2>
        <p style="color:#8ba3cb;">Your one-time login code:</p>
        <div style="font-size:40px;font-weight:bold;letter-spacing:12px;color:#ffffff;background:#050b14;padding:20px;border-radius:8px;text-align:center;border:1px solid #00f0ff;">${otp}</div>
        <p style="color:#8ba3cb;font-size:13px;margin-top:20px;">This code expires in <strong style="color:#ffb300;">10 minutes</strong>. Do not share it with anyone.</p>
        <p style="color:#ff1744;font-size:12px;">If you did not request this code, your admin panel may be under attack. Change your credentials immediately.</p>
      </div>
    `,
  });
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export default async (req: Request, context: Context) => {
  const store      = getStore({ name: "app-data", consistency: "strong" });
  const ip         = getClientIp(context);
  const headers    = securityHeaders();

  // ── Rate limiting: protect OTP endpoint from brute-force ─────────────────
  const rl = checkRateLimit(`admin-session:${ip}`);
  if (!rl.allowed) {
    console.warn(`[AUDIT] {"event":"RATE_LIMIT_EXCEEDED","ip":"${ip}"}`);
    return rateLimitExceededResponse(rl.retryAfterMs);
  }

  // Master admin email — must be set via ADMIN_EMAIL env var
  const adminEmail = process.env.ADMIN_EMAIL?.toLowerCase().trim();
  if (!adminEmail) {
    console.error(`[AUDIT] {"event":"CONFIG_ERROR","reason":"ADMIN_EMAIL not configured","ip":"${ip}"}`);
    return Response.json({ error: "Admin email not configured. Set ADMIN_EMAIL env var." }, { status: 503, headers });
  }
  const gmailUser        = process.env.GMAIL_USER || adminEmail;
  const gmailAppPassword = process.env.GMAIL_APP_PASSWORD || "";

  // The ADMIN_TOKEN env var is still required so other functions know the server is configured
  if (!process.env.ADMIN_TOKEN) {
    console.warn(`[AUDIT] {"event":"CONFIG_ERROR","reason":"ADMIN_TOKEN not configured","ip":"${ip}"}`);
    return Response.json({ error: "Server not configured" }, { status: 503, headers });
  }

  // ── POST /api/admin/session ──────────────────────────────────────────────
  if (req.method === "POST") {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return Response.json({ error: "Invalid JSON" }, { status: 400, headers });
    }

    const action = String(body.action ?? "");
    // ── direct-login: email + password (no OTP) ─────────────────────────────────────────────────
    if (action === "direct-login") {
      const email    = String(body.email    ?? "").toLowerCase().trim();
      const password = String(body.password ?? "").trim();

      const MAX_EMAIL_LEN = 254;
      const emailMatch = (() => {
        try {
          if (email.includes("\0")) return false;
          const aBuf = Buffer.alloc(MAX_EMAIL_LEN);
          const bBuf = Buffer.alloc(MAX_EMAIL_LEN);
          Buffer.from(email).copy(aBuf);
          Buffer.from(adminEmail).copy(bBuf);
          return timingSafeEqual(aBuf, bBuf);
        } catch { return false; }
      })();

      if (!emailMatch || !timingSafeTokenCompare(password, process.env.ADMIN_TOKEN!)) {
        console.warn(`[AUDIT] {"event":"DIRECT_LOGIN_FAILED","ip":"${ip}"}`);
        return Response.json({ error: "Invalid email or password." }, { status: 401, headers });
      }

      const { sessionId, expiresAt } = await createSession(store);
      console.log(`[AUDIT] {"event":"DIRECT_LOGIN_SUCCESS","sessionId":"${sessionId.slice(0, 8)}…","ip":"${ip}"}`);
      return Response.json(
        { sessionId, expiresAt, role: "master", message: "Authenticated." },
        { status: 201, headers }
      );
    }
    // ── Step 1: request-otp ─────────────────────────────────────────────────
    if (action === "request-otp") {
      const email = String(body.email ?? "").toLowerCase().trim();

      // Constant-time email comparison — fixed buffer size prevents length-based timing leaks.
      // Reject null bytes upfront (valid emails never contain them) to prevent null-padding bypass.
      const MAX_EMAIL_LEN = 254; // RFC 5321 maximum
      const emailMatch = (() => {
        try {
          if (email.includes("\0")) return false;
          const aBuf = Buffer.alloc(MAX_EMAIL_LEN);
          const bBuf = Buffer.alloc(MAX_EMAIL_LEN);
          Buffer.from(email).copy(aBuf);
          Buffer.from(adminEmail).copy(bBuf);
          return timingSafeEqual(aBuf, bBuf);
        } catch {
          return false;
        }
      })();

      if (!emailMatch) {
        // Respond with the same message as a valid request to prevent enumeration
        console.warn(`[AUDIT] {"event":"OTP_REQUEST_INVALID_EMAIL","ip":"${ip}"}`);
        return Response.json(
          { sent: true, message: "If this is a registered admin email, a code has been sent." },
          { status: 200, headers }
        );
      }

      if (!gmailAppPassword) {
        console.error(`[AUDIT] {"event":"CONFIG_ERROR","reason":"GMAIL_APP_PASSWORD not set","ip":"${ip}"}`);
        return Response.json({ error: "Email service not configured. Set GMAIL_APP_PASSWORD env var." }, { status: 503, headers });
      }

      const otp = generateOtp();
      const otpData: StoredOtp = {
        hash: hashOtp(otp),
        expiresAt: new Date(Date.now() + OTP_TTL_MS).toISOString(),
        createdAt: new Date().toISOString(),
        email: adminEmail,
        attempts: 0,
      };
      await store.setJSON(OTP_STORE_KEY, otpData);

      try {
        await sendOtpEmail(adminEmail, otp, gmailUser, gmailAppPassword);
        console.log(`[AUDIT] {"event":"OTP_SENT","email":"${adminEmail.slice(0, 4)}…","ip":"${ip}"}`);
      } catch (err) {
        // Clean up stored OTP if email fails
        await store.delete(OTP_STORE_KEY).catch(() => {});
        console.error(`[AUDIT] {"event":"OTP_SEND_FAILED","error":"${String(err)}","ip":"${ip}"}`);
        return Response.json({ error: "Failed to send verification email. Check GMAIL_APP_PASSWORD." }, { status: 502, headers });
      }

      return Response.json(
        { sent: true, message: "Verification code sent. Check your inbox." },
        { status: 200, headers }
      );
    }

    // ── Step 2: verify-otp ──────────────────────────────────────────────────
    if (action === "verify-otp") {
      const email     = String(body.email  ?? "").toLowerCase().trim();
      const otpInput  = String(body.otp    ?? "").trim();
      const twoFa     = String(body.twoFa  ?? "").trim();

      if (email !== adminEmail) {
        console.warn(`[AUDIT] {"event":"OTP_VERIFY_INVALID_EMAIL","ip":"${ip}"}`);
        return Response.json({ error: "Invalid code or email" }, { status: 401, headers });
      }

      if (!otpInput || !/^\d{6}$/.test(otpInput)) {
        return Response.json({ error: "Enter the 6-digit code from your email." }, { status: 400, headers });
      }

      // Validate 2FA code (ADMIN_TOKEN) before touching the OTP store
      if (!twoFa || !timingSafeTokenCompare(twoFa, process.env.ADMIN_TOKEN!)) {
        console.warn(`[AUDIT] {"event":"OTP_VERIFY_INVALID_2FA","ip":"${ip}"}`);
        return Response.json({ error: "Invalid 2FA code." }, { status: 401, headers });
      }

      const stored = await store.get(OTP_STORE_KEY, { type: "json" }) as StoredOtp | null;

      if (!stored || stored.email !== adminEmail) {
        return Response.json({ error: "No pending verification code. Request a new one." }, { status: 401, headers });
      }

      if (new Date(stored.expiresAt).getTime() < Date.now()) {
        await store.delete(OTP_STORE_KEY).catch(() => {});
        return Response.json({ error: "Code expired. Request a new one." }, { status: 401, headers });
      }

      // Increment attempt counter before checking
      stored.attempts = (stored.attempts || 0) + 1;
      if (stored.attempts > OTP_MAX_ATTEMPTS) {
        await store.delete(OTP_STORE_KEY).catch(() => {});
        console.warn(`[AUDIT] {"event":"OTP_MAX_ATTEMPTS_EXCEEDED","ip":"${ip}"}`);
        return Response.json({ error: "Too many failed attempts. Request a new code." }, { status: 401, headers });
      }
      await store.setJSON(OTP_STORE_KEY, stored);

      // Constant-time hash comparison
      const inputHash   = hashOtp(otpInput);
      const storedHash  = stored.hash;
      const hashMatch   = timingSafeTokenCompare(inputHash, storedHash);

      if (!hashMatch) {
        const remaining = OTP_MAX_ATTEMPTS - stored.attempts;
        console.warn(`[AUDIT] {"event":"OTP_VERIFY_FAILED","attempts":${stored.attempts},"ip":"${ip}"}`);
        return Response.json(
          { error: `Incorrect code. ${remaining} attempt${remaining === 1 ? "" : "s"} remaining.` },
          { status: 401, headers }
        );
      }

      // OTP correct — delete it (one-time use) and create session
      await store.delete(OTP_STORE_KEY).catch(() => {});
      const { sessionId, expiresAt } = await createSession(store);
      console.log(`[AUDIT] {"event":"SESSION_CREATED","sessionId":"${sessionId.slice(0, 8)}…","ip":"${ip}"}`);

      return Response.json(
        {
          sessionId,
          expiresAt,
          role: "master",
          message: "Authenticated. Use X-Session-Token header for admin operations.",
        },
        { status: 201, headers }
      );
    }

    if (action === "revoke-all") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        await persistAuditLog("AUTH_FAILURE", { operation: "revoke-all-sessions", reason: sessionResult.reason, ip }, store);
        return Response.json({ error: "Unauthorized" }, { status: 401, headers });
      }

      const revokedBefore = await revokeAllSessions(store);
      await destroySession(store);
      await persistAuditLog("ADMIN_WRITE", { operation: "revoke-all-sessions", revokedBefore, revoked: true, ip }, store);
      return Response.json({ success: true, revokedBefore }, { status: 200, headers });
    }

    return Response.json({ error: "Unknown action" }, { status: 400, headers });
  }

  // ── DELETE /api/admin/session → destroy session (logout) ────────────────
  if (req.method === "DELETE") {
    const sessionId = req.headers.get("X-Session-Token");
    if (sessionId) {
      await revokeSession(sessionId, store);
    }
    await destroySession(store);
    await persistAuditLog("ADMIN_WRITE", { operation: "logout", sessionId, revoked: Boolean(sessionId), ip }, store);
    return Response.json({ message: "Logged out" }, { status: 200, headers });
  }

  return new Response("Method not allowed", { status: 405, headers });
};

export const config: Config = {
  path: "/api/admin/session",
  method: ["POST", "DELETE"],
};
