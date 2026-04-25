# Contributing to NexusTrade

Thank you for your interest in contributing! This document explains the process for contributing code, documentation, and bug reports.

---

## Code of Conduct

Be respectful, constructive, and collaborative. We welcome contributors of all skill levels.

---

## Getting Started

### 1. Fork and Clone

```bash
# Fork via GitHub, then:
git clone https://github.com/YOUR_USERNAME/loquacious-gingersnap-26c121.git
cd loquacious-gingersnap-26c121
npm install
```

### 2. Set Up Environment

```bash
cp .env.example .env
# Edit .env with your local values (see README.md for details)
```

### 3. Run Locally

```bash
# Install Netlify CLI if not already installed
npm install -g netlify-cli

# Start local dev server
netlify dev
```

---

## Development Workflow

### Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feature/short-description` | `feature/add-staking-api` |
| Bug fix | `fix/short-description` | `fix/session-expiry-race` |
| Documentation | `docs/short-description` | `docs/update-api-reference` |
| Security | `security/short-description` | `security/harden-otp-flow` |

### Commit Messages

Use clear, descriptive commit messages:

```
feat: add staking rewards API endpoint
fix: prevent session token reuse after logout
docs: add admin setup guide to README
security: increase OTP entropy to 6 digits
```

### Pull Requests

1. Open a PR against `main`
2. Fill in the PR description explaining what changed and why
3. Reference any related issues (`Closes #123`)
4. Wait for code review before merging

---

## Code Style

### TypeScript (Netlify Functions)

- All functions are in `netlify/functions/*.mts` (TypeScript ESM)
- Import shared security utilities from `../lib/security.js` (resolves to `security.ts` via esbuild)
- Use `secureJson()` for all API responses — this applies security headers automatically
- Sanitize all user inputs with `sanitizeString()` before storage or processing
- Admin write operations must call `validateAdminSession()` and return 401 if invalid
- Log admin events with `auditLog()`

### Security Requirements

Every API function must:
1. Return a 503 if `ADMIN_TOKEN` is not configured, **at the top of the handler** (before any method dispatch), for all endpoints that gate any operation on `ADMIN_TOKEN`. Public-only endpoints that do not use `ADMIN_TOKEN` at all may omit this check.
2. Use `secureJson()` for all responses
3. Sanitize all string inputs
4. Validate admin session for any write operations that modify data

### Example Function Structure

```typescript
import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  sanitizeString,
  auditLog,
  getClientIp,
} from "../lib/security.js";

export default async (req: Request, context: Context) => {
  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (req.method === "GET") {
    const data = await store.get("my-key", { type: "json" });
    return secureJson(data || {}, 200, true);
  }

  if (req.method === "POST") {
    const sessionResult = await validateAdminSession(req, store);
    if (!sessionResult.valid) {
      auditLog("AUTH_FAILURE", { operation: "my-operation", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }

    const body = await req.json();
    const value = sanitizeString(body.value, 200);
    await store.setJSON("my-key", { value });

    auditLog("ADMIN_WRITE", { operation: "my-operation", ip });
    return secureJson({ success: true });
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/v2/my-endpoint",
  method: ["GET", "POST"],
};
```

---

## Testing

There is no automated test suite at this time. Before opening a PR:

1. Run `netlify dev` and manually test your changes
2. Test the `/api/v2/health` endpoint responds correctly
3. Test admin authentication flow end-to-end
4. Verify security headers are present on all responses
5. Check Netlify function logs for any errors

---

## Reporting Security Issues

**Do not open public GitHub issues for security vulnerabilities.**

Instead, email the maintainer directly. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## Questions

Open a GitHub Discussion or Issue for questions, feature requests, or general feedback.
