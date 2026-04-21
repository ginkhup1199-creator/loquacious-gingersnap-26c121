# Security Guide — NexusTrade Mobile Wallet DApp

This document describes the security practices and configuration required to run NexusTrade safely in production.

## Environment Variables

All secrets are managed through environment variables and **must never be committed to the repository**.

| Variable | Required | Description |
|---|---|---|
| `ADMIN_TOKEN` | ✅ Yes | Secret token required for all admin write operations |
| `NODE_ENV` | No | `development` or `production` (defaults to `development`) |

### Local Development Setup

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Fill in your actual values in `.env`.
3. The `.env` file is listed in `.gitignore` and will not be committed.

### Production Setup (Netlify)

1. Go to your [Netlify dashboard](https://app.netlify.com).
2. Select your site → **Site Settings** → **Build & Deploy** → **Environment Variables**.
3. Add the following variable:
   - **Key**: `ADMIN_TOKEN`
   - **Value**: A strong, randomly generated secret (minimum 32 characters recommended).
4. Save and trigger a new deployment.

## Admin Token Management

- The `ADMIN_TOKEN` is used as a server-configuration flag (returns 503 if absent) and as the password/2FA code in the admin login flow.
- It is compared server-side only — it is **never** sent back to the browser.
- If `ADMIN_TOKEN` is missing or incorrect, the login API returns `401 Unauthorized`.
- If `ADMIN_TOKEN` is not configured on the server, protected endpoints return `503 Service Unavailable`.

All admin write operations use the `X-Session-Token` request header, which carries the session ID
returned by a successful OTP or direct-login authentication call.

### Token Rotation

To rotate the admin token:
1. Generate a new strong token.
2. Update it in Netlify Environment Variables.
3. Update any admin clients or automation that use the token.
4. Trigger a new deployment.

## Repository Push & Modification Protection

This repository enforces source-code integrity through multiple layers. **The repository owner must complete the GitHub settings steps below** to activate full enforcement.

### Layer 1 — CODEOWNERS (in repo)

`.github/CODEOWNERS` declares `@ginkhup1199-creator` as the required reviewer for every file. This means no pull request that touches any source file can be merged without owner approval — once branch protection is enabled (see below).

### Layer 2 — CI Workflows (in repo)

Two GitHub Actions workflows run automatically:

| Workflow | File | Trigger | Purpose |
|---|---|---|---|
| Code Integrity Check | `.github/workflows/integrity-check.yml` | Every push & PR | TypeScript type-check + flags protected-file changes from non-owners in CI logs |
| PR Source-Code Guard | `.github/workflows/pr-guard.yml` | PR opened/updated touching source files | Auto-posts a warning comment on any PR from a non-owner |

### Layer 3 — Branch Protection Rules (must be set by repo owner in GitHub UI)

These settings **cannot be configured by a code commit** — they must be set manually:

1. Go to **GitHub → Repository → Settings → Branches → Add branch protection rule**
2. Set **Branch name pattern**: `main`
3. Enable all of the following:
   - ✅ **Require a pull request before merging** (set required approvals to **1**)
   - ✅ **Require approvals from Code Owners** (this activates CODEOWNERS enforcement)
   - ✅ **Require status checks to pass before merging** → add `TypeScript Type Check` and `Protected Files — Unauthorized Change Detection`
   - ✅ **Require branches to be up to date before merging**
   - ✅ **Do not allow bypassing the above settings**
   - ✅ **Restrict who can push to matching branches** → add only `ginkhup1199-creator`
   - ✅ **Block force pushes**
   - ✅ **Restrict deletions**

> Without completing Step 3, the CODEOWNERS file and CI workflows are active but merges are not blocked at the GitHub level. Step 3 is what makes protection mandatory and non-bypassable.



- **Write operations are admin-only**: Only requests with a valid `X-Admin-Token` can modify wallet data (addresses, features, withdrawals).
- **Read operations are public**: Wallet data can be read without authentication.
- **Rate limiting**: The API does not implement server-side per-IP rate limiting at the Netlify Functions layer. Operators who require rate limiting should configure it upstream (for example, via Netlify Edge Functions, a CDN, or a WAF).
- **Input validation**: All request bodies are validated before processing.

## What Is and Isn't Committed

| File | Committed | Reason |
|---|---|---|
| `.env.example` | ✅ Yes | Template only, no real secrets |
| `.env.production.example` | ✅ Yes | Template only, no real secrets |
| `.env` | ❌ No | Contains secrets — in `.gitignore` |
| `.env.production` | ❌ No | Contains secrets — in `.gitignore` |

## Reporting Security Issues

If you discover a security vulnerability, please do not open a public issue. Contact the repository owner directly.
