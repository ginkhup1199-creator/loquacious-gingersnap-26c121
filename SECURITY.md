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

- The `ADMIN_TOKEN` is required for all write operations on admin-protected endpoints.
- All requests must include the token in the `X-Admin-Token` request header.
- If the token is missing or incorrect, the API returns `401 Unauthorized`.
- If the token is not configured on the server, the API returns `503 Service Unavailable`.

### Token Rotation

To rotate the admin token:
1. Generate a new strong token.
2. Update it in Netlify Environment Variables.
3. Update any admin clients or automation that use the token.
4. Trigger a new deployment.

## Asset Protection

- **Write operations are admin-only**: Only requests with a valid `X-Admin-Token` can modify wallet data (addresses, features, withdrawals).
- **Read operations are public**: Wallet data can be read without authentication.
- **Rate limiting**: The API limits requests per IP to prevent brute force attacks.
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
