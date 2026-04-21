# NexusTrade Admin Dashboard — Production Deployment Guide

This document covers everything needed to deploy NexusTrade to **Netlify** and
operate the admin backend.

---

## Architecture Overview

```
your-site.netlify.app  (or your custom domain)
  ├─ index.html        → user-facing wallet app
  ├─ admin.html        → admin dashboard (protected by 2-step OTP)
  └─ /api/*            → Netlify Functions (serverless)
        ├─ /api/admin/session   → 2-step email OTP authentication
        ├─ /api/balances        → user balance management
        ├─ /api/kyc             → KYC approval workflows
        ├─ /api/withdrawals     → withdrawal processing
        ├─ /api/features        → feature toggle controls
        ├─ /api/trade-control   → trade outcome management
        ├─ /api/chat            → live chat support
        ├─ /api/audit-logs      → admin audit trail
        └─ /api/backup          → data backup & restore
```

All API functions run as Netlify serverless functions with `@netlify/blobs`
as the persistent data store. There is no separate database process.

---

## Pre-Deployment Checklist

- [ ] Gmail account with 2-Step Verification enabled
- [ ] Gmail App Password generated (16 chars)
- [ ] `ADMIN_TOKEN` generated: `openssl rand -hex 32`
- [ ] Node.js 18+ installed locally (for CLI tools)
- [ ] Netlify CLI installed: `npm install -g netlify-cli`

---

## Step 1 — Prepare Environment Variables

Copy the template and fill in real values:

```bash
cp .env.production.example .env.production
# Edit .env.production with your editor — never commit this file
```

Required variables:

| Variable | Description | How to get it |
|----------|-------------|---------------|
| `ADMIN_TOKEN` | Server-configured flag + write auth | `openssl rand -hex 32` |
| `ADMIN_EMAIL` | Email that receives OTP login codes | Your secure admin email |
| `GMAIL_USER` | Gmail address that *sends* OTP emails | Any Gmail account |
| `GMAIL_APP_PASSWORD` | Gmail App Password | [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) |
| `NODE_ENV` | Set to `production` | Literal string |

Optional variables (uncomment in `.env.production.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_MAX` | `30` | Max requests per IP per window |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate limit window in ms |
| `APP_VERSION` | package version | Shown in `/api/health` |

---

## Step 2 — Deploy to Netlify (Primary Method)

The Netlify deployment hosts both the frontend and all API functions.

### 2a. Create the Netlify Site

```bash
# Authenticate with Netlify
netlify login

# Link to your existing site or create a new one
netlify init
```

Or via Netlify web UI:
1. Go to [app.netlify.com](https://app.netlify.com)
2. **Add new site → Import an existing project**
3. Select your Git provider and this repository
4. Build settings are auto-detected from `netlify.toml`

### 2b. Configure Environment Variables

In the Netlify dashboard: **Site settings → Environment variables → Add variable**

Add every variable from `.env.production.example` with real values.

Alternatively, push them from the CLI:

```bash
netlify env:set ADMIN_TOKEN        "$(openssl rand -hex 32)"
netlify env:set ADMIN_EMAIL        "your-admin@example.com"
netlify env:set GMAIL_USER         "your-sender@gmail.com"
netlify env:set GMAIL_APP_PASSWORD "your16charpassword"
netlify env:set NODE_ENV           "production"
```

### 2c. Deploy

```bash
# Deploy to production
netlify deploy --prod
```

Or push to `main` branch — Netlify auto-deploys on every push.

---

## Step 3 — Verify the Deployment

### Health Check

```bash
BASE=https://your-site.netlify.app

curl $BASE/api/health
# Expected: { "status": "ok", "timestamp": "...", "version": "1.0.0" }
```

### Admin Login Flow

1. Navigate to `https://your-site.netlify.app/admin.html`
2. Enter the `ADMIN_EMAIL` address and click **Send OTP**
3. Check inbox for the 6-digit code
4. Enter code → click **Verify** → admin dashboard loads

### API Endpoints Smoke Test

```bash
BASE=https://your-site.netlify.app

# Public endpoints (no auth required)
curl $BASE/api/health
curl $BASE/api/market-data
curl $BASE/api/settings
curl $BASE/api/features
curl $BASE/api/levels

# All should return 200, not 503
```

### Security Headers

```bash
curl -I $BASE/api/health
# Must include:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Cache-Control: no-store, no-cache, must-revalidate, private
```

---

## Step 4 — Admin Operations Reference

All admin write operations require the `X-Session-Token` header with the
session ID obtained from the OTP login flow.

### Authentication

```bash
# Step 1: Request OTP
curl -X POST $BASE/api/admin/session \
  -H "Content-Type: application/json" \
  -d '{"action":"request-otp","email":"your-admin@example.com"}'

# Step 2: Verify OTP
curl -X POST $BASE/api/admin/session \
  -H "Content-Type: application/json" \
  -d '{"action":"verify-otp","email":"your-admin@example.com","otp":"123456"}'
# Returns: { "sessionId": "...", "expiresAt": "..." }

SESSION=<sessionId from above>
```

### User Balance Management

```bash
curl -X POST $BASE/api/balances \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: $SESSION" \
  -d '{"wallet":"0xABC...","usdt":1000}'
```

### KYC Approval

```bash
# List pending KYC submissions
curl $BASE/api/kyc?list=true \
  -H "X-Session-Token: $SESSION"

# Approve a KYC submission
curl -X POST $BASE/api/kyc \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: $SESSION" \
  -d '{"wallet":"0xABC...","status":"approved"}'
```

### Withdrawal Processing

```bash
# List all withdrawals
curl $BASE/api/withdrawals \
  -H "X-Session-Token: $SESSION"

# Approve a withdrawal
curl -X POST $BASE/api/withdrawals \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: $SESSION" \
  -d '{"id":"withdrawal-id","status":"completed"}'
```

### Feature Toggles

```bash
# Disable binary options feature
curl -X POST $BASE/api/features \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: $SESSION" \
  -d '{"binary":false}'
```

### Trade Outcome Control

```bash
# Force next trade for a wallet to win
curl -X POST $BASE/api/trade-control \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: $SESSION" \
  -d '{"wallet":"0xABC...","outcome":"win"}'
```

### Database Backup

```bash
# Export full data snapshot
curl $BASE/api/backup \
  -H "X-Session-Token: $SESSION" \
  -o backup-$(date +%Y%m%d).json

# Restore from snapshot (wrap the exported file in the required envelope)
# The exported file is used as the value of the "snapshot" key
curl -X POST $BASE/api/backup \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: $SESSION" \
  -d "{\"snapshot\": $(cat backup-20240101.json)}"
```

> **Note:** Restore expects `{ "snapshot": <exported-object> }`.
> If the exported JSON is very large, pipe it through `jq` or use a helper script
> to build the envelope rather than shell string interpolation.

### Audit Logs

```bash
# Retrieve last 500 audit events
curl $BASE/api/audit-logs \
  -H "X-Session-Token: $SESSION"
```

---

## Step 5 — Security Hardening

### Rate Limiting

Rate limiting is enabled by default on the admin session endpoint (OTP requests
and verifications) to mitigate brute-force attacks. Defaults:

- **30 requests per IP per minute** (per function process)

Adjust via environment variables:

```
RATE_LIMIT_MAX=20          # Stricter: 20 requests per window
RATE_LIMIT_WINDOW_MS=60000 # 1-minute window
```

### Branch Protection (Git Lockdown)

After deployment, protect the `main` branch in GitHub:

1. Go to **Settings → Branches → Add rule**
2. Branch name pattern: `main`
3. Enable:
   - ✅ Require pull request reviews before merging
   - ✅ Require status checks to pass before merging
   - ✅ Include administrators
4. Click **Create**

This prevents direct pushes to `main` without review.

### Rotating Credentials

To rotate `ADMIN_TOKEN` or `GMAIL_APP_PASSWORD`:

1. Generate a new value: `openssl rand -hex 32`
2. Update in Netlify dashboard → Environment Variables
3. Trigger a redeploy (environment variables take effect on next deploy)
4. Existing sessions expire naturally within 1 hour

---

## Monitoring & Maintenance

### Netlify Function Logs

- Netlify dashboard → **Functions** tab → select a function → view logs
- Audit events appear as `[AUDIT] {...}` JSON lines
- Watch for repeated `AUTH_FAILURE` events (brute-force indicator)

### Regular Backups

Schedule a periodic backup export using a cron service or Netlify Scheduled
Functions:

```bash
# Export backup (add to cron or CI job)
curl -s $BASE/api/backup \
  -H "X-Session-Token: $SESSION" \
  > backups/nexustrade-$(date +%Y%m%d-%H%M%S).json
```

---

## Rollback

```bash
netlify rollback
```

Or in Netlify dashboard: **Deploys → select a previous deploy → Publish deploy**

---

## Checklist Summary

```
PRE-DEPLOYMENT
[ ] Gmail App Password ready
[ ] ADMIN_TOKEN generated (32+ chars, openssl rand -hex 32)
[ ] No secrets committed to Git

NETLIFY DEPLOYMENT
[ ] Netlify site linked to repository
[ ] All environment variables set in Netlify dashboard
[ ] netlify deploy --prod succeeded
[ ] /api/health returns { "status": "ok" }

ADMIN VERIFICATION
[ ] OTP login flow works end-to-end
[ ] Admin dashboard loads after login
[ ] Balance update works
[ ] Feature toggle works
[ ] Backup export returns valid JSON
[ ] Audit logs visible

SECURITY
[ ] Branch protection enabled on main
[ ] CODEOWNERS review required for all protected paths
[ ] Rate limiting confirmed (verify 429 after >30 rapid requests)
[ ] Security headers present (curl -I /api/health)
[ ] LLM injection blocked (curl /api/chat with injection payload → 400)
[ ] No hardcoded secrets anywhere in source
```
