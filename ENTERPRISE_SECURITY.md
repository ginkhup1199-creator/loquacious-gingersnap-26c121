# Enterprise Security Policy — NexusTrade DApp

## Overview

NexusTrade implements enterprise-grade security controls to protect user assets,
prevent unauthorized access, and defend against modern AI-assisted threats.

---

## Access Control Model

### Enterprise-Only Administration

- **Team access is completely disabled.** There are no shared team credentials,
  group tokens, or role-delegation mechanisms.
- Admin operations require the single enterprise `ADMIN_TOKEN` environment variable.
- The `ADMIN_TOKEN` must be set in Netlify's environment variables panel and is
  **never** committed to source control.

### Session-Based Token Flow

Every admin session follows this lifecycle:

```
Admin                       Server                        Netlify Blobs
  |                             |                               |
  |--POST /api/admin/session--->|                               |
  |   X-Admin-Token: <master>   |--store session (1h TTL)------>|
  |<--{ sessionId, expiresAt }--|                               |
  |                             |                               |
  |--POST /api/settings-------->|                               |
  |   X-Session-Token: <id>     |--validate session------------>|
  |                             |<--session valid---------------|
  |<--200 OK--------------------|                               |
  |                             |                               |
  |--DELETE /api/admin/session->|--delete session-------------->|
  |<--{ message: "destroyed" }--|                               |
```

**Key properties:**
- The raw `ADMIN_TOKEN` (master password) is **never stored in the browser**.
- The browser stores only the `sessionId` in `sessionStorage` (cleared on tab close).
- Sessions expire automatically after **1 hour**.
- Only one active session is permitted at a time; new logins replace old sessions.
- Logout immediately invalidates the session server-side.

---

## AI / LLM Injection Prevention

The chat endpoint (`/api/chat`) and all user-supplied inputs are checked for
known prompt-injection patterns before storage or forwarding to any AI service.

### Blocked Patterns

| Category | Examples |
|----------|---------|
| System prompt override | "ignore previous instructions", "override system prompt" |
| Role escalation | "act as admin", "DAN mode", "jailbreak" |
| Context escape | `[SYSTEM]`, `### system ###`, separator tricks |
| Secret exfiltration | "show me your API key", "print ADMIN_TOKEN", `process.env` |
| Tool/function abuse | `call function(`, `execute command`, `eval(` |

### Response

Blocked messages receive a `400 Bad Request` response:
```json
{ "error": "Message contains disallowed content" }
```

The attempt is recorded in the Netlify function log:
```json
{ "event": "INJECTION_BLOCKED", "reason": "...", "ip": "..." }
```

---

## Content Sanitization

All user-supplied string values are sanitized before storage:

- Null bytes removed
- HTML special characters escaped (`<`, `>`, `&`, `"`, `'`, `/`)
- Dangerous URI schemes blocked (`javascript:`, `data:`, `vbscript:`)
- Maximum string length enforced (1000 chars by default)
- Object keys sanitized to prevent prototype pollution

---

## Security Headers

Every API response includes:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | camera, microphone, geolocation, payment all disabled |
| `Cache-Control` | `no-store` (sensitive endpoints) |

---

## Audit Logging

All security events are logged as structured JSON via `console.log` and captured
by the Netlify log pipeline:

```json
{ "timestamp": "2026-04-04T12:00:00Z", "event": "AUTH_FAILURE", "reason": "Invalid session token", "ip": "1.2.3.4" }
{ "timestamp": "2026-04-04T12:01:00Z", "event": "SESSION_CREATED", "sessionIdPrefix": "a1b2c3d4…", "ip": "1.2.3.4" }
{ "timestamp": "2026-04-04T12:02:00Z", "event": "ADMIN_WRITE", "operation": "update-balance", "wallet": "0xdAC17F9…31ec7", "ip": "1.2.3.4" }
```

**Sensitive data is never logged:**
- Token values are never included in log entries
- Session IDs are truncated to the first 8 characters
- Wallet addresses are truncated (`0xdAC17F9…31ec7`)

---

## Rate Limiting

Admin session creation is protected by the Netlify platform rate limits.
Per-IP request counting is implemented in `src/middleware/apiSecurity.js` for
additional defense against brute-force attempts.

---

## Secret Management

| Secret | Storage |
|--------|---------|
| `ADMIN_TOKEN` | Netlify environment variable only |
| Session tokens | `@netlify/blobs` (server-side, 1-hour TTL) |
| Browser storage | `sessionToken` in `sessionStorage` only (no `localStorage`) |

**Never commit** `.env`, `.env.production`, or any file containing real credentials.
The `.gitignore` is configured to block these automatically.

---

## Generating a Secure Admin Token

```bash
# macOS / Linux
openssl rand -hex 32

# Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Set the output value as `ADMIN_TOKEN` in Netlify:
**Site Settings → Build & Deploy → Environment Variables**

---

## Incident Response

1. If `ADMIN_TOKEN` is suspected compromised:
   - Immediately rotate the token in Netlify environment variables
   - Trigger a new deployment to invalidate all active sessions
   - Review Netlify function logs for suspicious `ADMIN_WRITE` events

2. If a session token is suspected compromised:
   - Rotating `ADMIN_TOKEN` and redeploying invalidates all sessions (the session
     store is checked against the current `ADMIN_TOKEN` being set on the server)

---

## Compliance Notes

- All admin write operations are audit-logged with timestamp and IP
- Session tokens expire automatically (no indefinite access)
- No sensitive data is stored in browser `localStorage`
- Secrets are managed exclusively through environment variables
