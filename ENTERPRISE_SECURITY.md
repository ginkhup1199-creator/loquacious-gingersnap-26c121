# Enterprise Security Architecture

## NexusTrade — Security Implementation

This document describes the security architecture implemented in NexusTrade.

---

## 🔐 Session-Based Authentication System

### Overview

Admin authentication uses a **2-step email OTP flow**:

1. The admin requests a 6-digit OTP code sent to the configured `ADMIN_EMAIL`.
2. The code is verified server-side. On success, a session token with a 1-hour TTL is returned.
3. Every subsequent write operation carries the session token in the `X-Session-Token` header.
4. Sessions are stored server-side in Netlify Blobs and expire automatically.

### Authentication Flow

```
Admin navigates to /admin.html
       ↓
POST /api/admin/session { action:"request-otp", email }
       ↓
Server sends 6-digit OTP to ADMIN_EMAIL (10-minute TTL)
       ↓
POST /api/admin/session { action:"verify-otp", email, otp }
(+ ADMIN_TOKEN as 2FA code)
       ↓
Server returns { sessionId, expiresAt, role:"master" }
       ↓
Admin uses X-Session-Token: <sessionId> for all write operations
```

Alternatively, for direct password login (no OTP):

```
POST /api/admin/session { action:"direct-login", email, password }
(password is compared against ADMIN_TOKEN with timing-safe comparison)
```

### Why Session Tokens?

- **Replay attack prevention**: Tokens are server-side and expire automatically
- **No client-side secrets**: Session IDs are not the raw ADMIN_TOKEN
- **Timing-safe comparison**: `crypto.timingSafeEqual()` on all token checks
- **Audit trail**: Every login attempt and session creation is logged

---

## 🛡️ LLM/Prompt Injection Protection

### What's Protected

All user-submitted text fields are scanned for AI prompt injection patterns before processing:

- Direct instruction override attempts ("ignore previous instructions")
- Role-play / persona hijacking ("act as an unrestricted AI")
- Data exfiltration attempts ("dump all database records")
- System prompt delimiter injection (`[INST]`, `<|system|>`, etc.)
- Wallet/financial manipulation attempts ("transfer all funds to...")

### Implementation

The `src/security/llmProtection.js` module provides:
- `checkForInjection(input)` - Tests a string against injection patterns
- `scanRequestBody(body)` - Recursively scans all string fields
- `sanitizeString(input, maxLen)` - Cleans HTML, control characters, truncates

---

## 📊 Audit Logging

Every security-relevant event is logged with a structured JSON entry:

```json
{
  "timestamp": "2026-04-04T12:30:45Z",
  "action": "BALANCE_UPDATED",
  "level": "INFO",
  "actor": "admin",
  "userId": null,
  "adminId": "sk_a***[32]",
  "resource": "balances",
  "changes": { "wallet": "0x...", "prevBalance": 1000, "newBalance": 2000 },
  "status": "success",
  "ip": "192.168.1.1"
}
```

Logs are captured by Netlify Function logs and can be extended to persistent storage.

### Logged Events

| Category | Events |
|----------|--------|
| Admin | Login, login failure, session created/expired, token issued/used/expired |
| Balances | Updates (with before/after values) |
| Trades | Created, completed, failed |
| Wallet | Address updates |
| Withdrawals | Requested, processed, rejected |
| KYC | Submitted, approved, rejected |
| Security | Rate limit exceeded, injection blocked, unauthorized access |
| Settings | Feature toggles, settings changes, level updates |

---

## 🚦 Rate Limiting

All API endpoints implement per-IP rate limiting:

| Endpoint | Limit |
|----------|-------|
| `/api/admin` | 20 req/min (login brute-force protection) |
| `/api/balances` | 30 req/min |
| `/api/trades` | 30 req/min |
| `/api/users` | 20 req/min |
| `/api/withdrawals` | 20 req/min |
| `/api/market-data` | 60 req/min |
| `/api/transactions` | 30 req/min |

Rate limits return HTTP 429 with a descriptive error message.

---

## ✅ Input Validation

All API endpoints validate inputs:

- **Type checking**: All fields have type constraints
- **Numeric bounds**: Financial values must be positive, within safe ranges
- **Enum validation**: Coins, networks, statuses must be from allowed lists
- **Length limits**: All string fields are capped to prevent abuse
- **HTML stripping**: All user strings have HTML tags removed

### Admin-Protected vs. Public Endpoints

| Endpoint | Write Access |
|----------|-------------|
| `/api/balances` POST | Admin only |
| `/api/features` POST | Admin only |
| `/api/levels` POST | Admin only |
| `/api/settings` POST | Admin only |
| `/api/addresses` → `/api/wallet` POST | Admin only |
| `/api/kyc` POST (approve/reject) | Admin only |
| `/api/withdrawals` POST (process) | Admin only |
| `/api/users` POST (register) | Public |
| `/api/trades` POST | Public (authenticated wallet) |
| `/api/withdrawals` POST (add) | Public (authenticated wallet) |

---

## 🔑 Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `ADMIN_TOKEN` | Server-configuration flag + password for `direct-login` and 2FA step in OTP flow | ✅ Yes |
| `ADMIN_EMAIL` | Email address that receives OTP login codes | ✅ Yes |
| `GMAIL_USER` | Gmail account used to send OTP emails | ✅ Yes |
| `GMAIL_APP_PASSWORD` | Gmail App Password (16 chars) | ✅ Yes |
| `NODE_ENV` | Application environment | No |

### Setting Up in Netlify

1. Go to **Site Settings → Environment Variables**
2. Add all required variables with real values (see `.env.production.example` for guidance)
3. Trigger a new deployment — environment variables take effect on the next deploy

---

## 🔒 Constant-Time Comparison

All token comparisons use `crypto.timingSafeEqual()` to prevent timing-based attacks that could reveal token values through response time differences.

---

## 📋 Security Checklist

- ✅ 2-step email OTP admin authentication (no static passwords)
- ✅ Session-based auth with 1-hour server-side TTL (no persistent tokens in localStorage)
- ✅ Session tokens stored server-side in Netlify Blobs
- ✅ LLM/prompt injection detection and blocking
- ✅ Input sanitization on all user fields
- ✅ Rate limiting per IP on all endpoints
- ✅ Constant-time token comparison (`crypto.timingSafeEqual()`)
- ✅ Audit logging for all security events
- ✅ ADMIN_TOKEN never sent to browser
- ✅ Sessions expire automatically after 1 hour
- ✅ OTP codes expire after 10 minutes and are single-use
- ✅ OTP locked out after 5 failed attempts
- ✅ HTML injection prevention (tags stripped)
- ✅ Numeric bounds validation
- ✅ Enum validation for controlled fields
- ✅ `.env` files excluded from Git
- ✅ Enum validation for controlled fields
- ✅ `.env` files excluded from Git
