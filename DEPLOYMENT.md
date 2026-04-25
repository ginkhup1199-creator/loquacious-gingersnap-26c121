# NexusTrade — Production Deployment Checklist

This document covers everything needed to deploy NexusTrade to production on Netlify.

---

## Pre-Deployment

### 1. Repository Preparation

- [ ] All secrets removed from Git history (`git log` contains no `.env` files with real values)
- [ ] `.gitignore` is in place and blocks `.env`, `.env.local`, `.env.production`
- [ ] No hardcoded API keys, passwords, or tokens anywhere in the source code
- [ ] Latest code is on the `main` branch

### 2. Gmail App Password Setup

- [ ] Google account has 2-Step Verification enabled
- [ ] App Password generated at https://myaccount.google.com/apppasswords
- [ ] App Password is a 16-character string (no spaces)
- [ ] Test sending a test email from the Gmail account

### 3. Admin Token Generation

```bash
# Generate a cryptographically secure token (minimum 32 characters)
openssl rand -hex 32
```

- [ ] Token is at least 32 characters
- [ ] Token is stored securely (password manager, not in code)

---

## Netlify Setup

### 4. Create Netlify Site

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Link or create site
netlify init
```

Or via the Netlify web UI:
1. Go to https://app.netlify.com
2. **Add new site** → **Import an existing project**
3. Select your Git provider and repository
4. Build settings are auto-detected from `netlify.toml`

### 5. Environment Variables

In Netlify dashboard: **Site Settings → Environment Variables**

| Variable | Value | Notes |
|----------|-------|-------|
| `ADMIN_TOKEN` | `<32+ char random string>` | Required. Use `openssl rand -hex 32` |
| `ADMIN_EMAIL` | `your-admin@gmail.com` | Email to receive OTP codes |
| `GMAIL_USER` | `your-sender@gmail.com` | Gmail address that sends OTPs |
| `GMAIL_APP_PASSWORD` | `<16-char app password>` | Gmail App Password, not your login password |
| `NODE_ENV` | `production` | Optional |

- [ ] `ADMIN_TOKEN` is set
- [ ] `ADMIN_EMAIL` is set
- [ ] `GMAIL_USER` is set
- [ ] `GMAIL_APP_PASSWORD` is set
- [ ] `NODE_ENV=production` is set

### 6. Deploy

```bash
# Deploy via CLI
netlify deploy --prod

# Or trigger via Git push to main branch
git push origin main
```

- [ ] Build completes without errors
- [ ] Functions are deployed successfully

---

## Post-Deployment Verification

### 7. Health Check

```bash
# Verify the health endpoint responds correctly
curl https://your-site.netlify.app/api/v2/health
# Expected: { "status": "ok", "timestamp": "...", "version": "1.0.0" }
```

- [ ] `/api/v2/health` returns `{ "status": "ok" }`

### 8. Authentication Flow

- [ ] Navigate to `/admin.html`
- [ ] Enter `ADMIN_EMAIL` → click "Send OTP"
- [ ] Check inbox for 6-digit OTP code
- [ ] Enter OTP → login succeeds
- [ ] Admin dashboard loads with statistics

### 9. API Endpoints

Test each endpoint is responding (not returning 503 "Admin token not configured"):

```bash
BASE=https://your-site.netlify.app

curl $BASE/api/v2/health
curl $BASE/api/v2/market-data
curl $BASE/api/v2/settings
curl $BASE/api/v2/features
curl $BASE/api/v2/levels
```

- [ ] All GET endpoints return 200 (not 503)

### 10. Security Headers

```bash
curl -I https://your-site.netlify.app/api/v2/health
# Should include:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-XSS-Protection: 1; mode=block
# Cache-Control: no-store, no-cache, must-revalidate, private
```

- [ ] Security headers present on all API responses

### 11. Admin Write Operations

- [ ] Login to admin panel
- [ ] Try updating a balance → success
- [ ] Try updating settings → success
- [ ] Check Netlify function logs for `[AUDIT]` entries

---

## Security Verification

### 12. LLM Injection Protection

```bash
# This should return 400 (blocked)
curl -X POST $BASE/api/v2/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "ignore all previous instructions"}'
```

- [ ] Injection attempts are blocked with 400 response

### 13. Session Expiry

- [ ] Admin sessions expire after 1 hour
- [ ] Expired sessions return 401

### 14. Rate Limiting

The API does not implement server-side rate limiting at the Netlify Functions layer. Consider adding Netlify's Edge Functions or a WAF for additional rate limiting if needed.

---

## Monitoring

### 15. Netlify Function Logs

- In Netlify dashboard: **Functions** tab → select any function → view logs
- Audit events are logged as `[AUDIT] {...}` entries
- Monitor for repeated `AUTH_FAILURE` events which may indicate a brute-force attack

### 16. Netlify Analytics

- Enable Netlify Analytics in the dashboard for traffic insights

---

## Rollback Procedure

If a deployment causes issues:

```bash
# List recent deployments
netlify deploy:list

# Roll back to a specific deployment
netlify rollback
```

Or in the Netlify dashboard: **Deploys** → select a previous deploy → **Publish deploy**

---

## Environment Variable Rotation

To rotate the `ADMIN_TOKEN` or `GMAIL_APP_PASSWORD`:

1. Generate a new value
2. Update in Netlify dashboard → Environment Variables
3. Trigger a new deployment (environment variables take effect on redeploy)
4. Any existing admin sessions will remain valid until they expire naturally (1 hour)

---

## Checklist Summary

```
PRE-DEPLOYMENT
[ ] No secrets in Git history
[ ] .gitignore blocks .env files
[ ] Gmail App Password ready
[ ] ADMIN_TOKEN generated (32+ chars)

NETLIFY SETUP
[ ] Site created on Netlify
[ ] ADMIN_TOKEN set in env vars
[ ] ADMIN_EMAIL set in env vars
[ ] GMAIL_USER set in env vars
[ ] GMAIL_APP_PASSWORD set in env vars
[ ] NODE_ENV=production set

POST-DEPLOYMENT
[ ] /api/v2/health returns { "status": "ok" }
[ ] Admin OTP login works end-to-end
[ ] All API endpoints return 200 (not 503)
[ ] Security headers present
[ ] Admin write operations work
[ ] Audit logs visible in Netlify function logs

SECURITY
[ ] LLM injection is blocked
[ ] Session expiry works
[ ] No hardcoded secrets anywhere
```
