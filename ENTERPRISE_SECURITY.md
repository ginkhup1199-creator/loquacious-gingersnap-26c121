# Enterprise Security Architecture

## NexusTrade - Enterprise-Grade Security Implementation

This document describes the enterprise security architecture implemented in NexusTrade.

---

## 🔐 Session-Based One-Time Token System

### Overview

Admin authentication uses a **multi-layer session system** where:
1. The admin authenticates once per session with `ENTERPRISE_SECRET` to create a server-side session
2. Every subsequent **write operation** requires a fresh **one-time token** that is immediately invalidated after use
3. Sessions expire automatically after 30 minutes of inactivity
4. Tokens expire after 5 minutes if not used

### Authentication Flow

```
Admin enters password
       ↓
POST /api/admin?action=login
(with ENTERPRISE_SECRET credential)
       ↓
Server creates session → returns sessionId
       ↓
For each write operation:
  POST /api/admin?action=issue-token
  (with sessionId)
       ↓
  Server issues one-time token (valid 5 min)
       ↓
  Admin uses token in X-Admin-Token header
       ↓
  Token is IMMEDIATELY INVALIDATED after first use
       ↓
  Next write requires a NEW token request
```

### Why One-Time Tokens?

- **Replay attack prevention**: Captured tokens cannot be reused
- **Session isolation**: Each admin action is explicitly re-authorized
- **Audit trail**: Every token issuance and use is logged
- **Time-bound**: Tokens expire even if not used

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
| `ADMIN_TOKEN` | Validates admin write requests (X-Admin-Token header) | ✅ Yes |
| `ENTERPRISE_SECRET` | Creates admin sessions (defaults to ADMIN_TOKEN) | Optional |
| `NODE_ENV` | Application environment | No |

### Setting Up in Netlify

1. Go to **Site Settings → Build & Deploy → Environment Variables**
2. Add `ADMIN_TOKEN` with a strong random value (minimum 32 characters)
3. Optionally add `ENTERPRISE_SECRET` for additional separation
4. Trigger a new deployment

---

## 🔒 Constant-Time Comparison

All token comparisons use `crypto.timingSafeEqual()` to prevent timing-based attacks that could reveal token values through response time differences.

---

## 📋 Security Checklist

- ✅ Session-based admin authentication (no persistent tokens in localStorage)
- ✅ One-time tokens for each write operation
- ✅ LLM/prompt injection detection and blocking
- ✅ Input sanitization on all user fields
- ✅ Rate limiting per IP on all endpoints
- ✅ Constant-time token comparison
- ✅ Audit logging for all security events
- ✅ Admin token never stored in browser after login
- ✅ Session expires automatically (30 min)
- ✅ Tokens expire after 5 minutes
- ✅ HTML injection prevention (tags stripped)
- ✅ Numeric bounds validation
- ✅ Enum validation for controlled fields
- ✅ `.env` files excluded from Git
