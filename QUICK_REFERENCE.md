# NexusTrade Quick Reference Guide

**Last Updated:** 2026-04-30

---

## 📌 Quick Module Reference

### Authentication Modules

#### `sessionTokens.js`
**Purpose:** In-memory single-use token management  
**Key Functions:**
- `generateSecureToken(bytes)` → Random hex token
- `createSession(enterpriseId)` → New session
- `issueOneTimeToken(sessionId)` → Single-use token
- `validateAndConsumeToken(sessionId, token)` → Validate & consume
- `validateSession(sessionId)` → Check session validity
- `destroySession(sessionId)` → Logout
- `cleanExpiredSessions()` → Memory cleanup

**Usage:**
```javascript
const st = require('./src/auth/sessionTokens');

const sess = st.createSession('ent-123');
const tok = st.issueOneTimeToken(sess.sessionId);
const result = st.validateAndConsumeToken(sess.sessionId, tok.token);
if (result.valid) {
  console.log(result.enterpriseId);
}
```

---

#### `sessionManager.js`
**Purpose:** Persistent session storage (Netlify Blobs)  
**Key Functions:**
- `createSession(store)` → Async session creation
- `validateSession(store, sessionId)` → Async validation
- `markSessionUsed(store, session)` → Mark as used
- `destroySession(store)` → Logout

**Usage:**
```javascript
const sm = require('./src/auth/sessionManager');

const sess = await sm.createSession(store);
const result = await sm.validateSession(store, sessionId);
if (result.valid) {
  await sm.markSessionUsed(store, result.session);
}
```

---

#### `adminAuth.js`
**Purpose:** Admin token validation  
**Key Functions:**
- `validateAdminToken(token)` → Check token
- `logAdminOperation(operation, success)` → Log action
- `unauthorizedResponse(reason)` → 401 response

**Usage:**
```javascript
const aa = require('./src/auth/adminAuth');

const result = aa.validateAdminToken(req.headers.get('X-Admin-Token'));
if (!result.authorized) {
  return aa.unauthorizedResponse(result.reason);
}
```

---

#### `enterpriseAuth.js`
**Purpose:** Enterprise-only access control  
**Key Functions:**
- `validateEnterpriseToken(token)` → Enterprise validation
- `isTeamAccessAttempt(token)` → Detect team credentials
- `forbiddenResponse(detail)` → 403 response

**Usage:**
```javascript
const ea = require('./src/auth/enterpriseAuth');

const result = ea.validateEnterpriseToken(token);
if (!result.authorized) {
  return ea.forbiddenResponse(result.reason);
}
```

---

### Security Modules

#### `llmProtection.js`
**Purpose:** Prompt injection detection  
**Key Functions:**
- `checkForInjection(input)` → Check string
- `sanitizeString(input, maxLength)` → Clean string
- `scanRequestBody(body, fieldsToCheck)` → Scan object
- `injectionBlockedResponse()` → 400 response

**Usage:**
```javascript
const lp = require('./src/security/llmProtection');

const check = lp.checkForInjection(userInput);
if (!check.safe) {
  return lp.injectionBlockedResponse();
}

const scan = lp.scanRequestBody(req.body);
if (!scan.safe) {
  return lp.injectionBlockedResponse();
}
```

---

#### `llmSafetyFilter.js`
**Purpose:** LLM input/output filtering  
**Key Functions:**
- `filterLLMInput(input)` → Validate user input
- `filterLLMOutput(output)` → Redact sensitive output
- `containsInjectionPattern(input)` → Quick check

**Usage:**
```javascript
const lf = require('./src/security/llmSafetyFilter');

const input = lf.filterLLMInput(userMessage);
if (!input.safe) {
  return error(input.reason);
}

const response = await callLLM(input.sanitized);
const clean = lf.filterLLMOutput(response);
```

---

#### `contentSanitizer.js`
**Purpose:** XSS & input sanitization  
**Key Functions:**
- `sanitizeString(value, options)` → Clean string
- `sanitizeObject(data, options)` → Recursive clean
- `sanitizeWalletAddress(address)` → Validate wallet
- `escapeHtml(value)` → HTML escape

**Usage:**
```javascript
const cs = require('./src/security/contentSanitizer');

const clean = cs.sanitizeString(userInput);
const cleanData = cs.sanitizeObject(req.body);
const wallet = cs.sanitizeWalletAddress(address);
if (wallet.valid) {
  // Use wallet.address (lowercase)
}
```

---

### Middleware & Config

#### `apiSecurity.js`
**Purpose:** Rate limiting & token validation  
**Key Functions:**
- `validateAdminToken(req)` → Check token header
- `applyRateLimit(ip)` → Rate limit check
- `validateRequestBody(body)` → Validate structure

**Usage:**
```javascript
const as = require('./src/middleware/apiSecurity');

const token = as.validateAdminToken(request);
if (!token.valid) {
  return token.response;
}

const limit = as.applyRateLimit(clientIP);
if (limit.limited) {
  return limit.response;
}

if (!as.validateRequestBody(body)) {
  return Response.json({ error: "Invalid body" }, { status: 400 });
}
```

---

#### `securityHeaders.js`
**Purpose:** HTTP security headers  
**Key Functions:**
- `getSecurityHeaders(options)` → Get headers object
- `applySecurityHeaders(headers, options)` → Apply to Headers
- `secureJsonResponse(body, options)` → Create safe response

**Usage:**
```javascript
const sh = require('./src/config/securityHeaders');

const headers = sh.getSecurityHeaders();
const resp = sh.secureJsonResponse({ data: "..." }, { status: 200 });
```

---

#### `validateEnv.js`
**Purpose:** Environment validation  
**Key Functions:**
- `validateEnv()` → Validate all required vars
- `getConfig()` → Get validated config

**Usage:**
```javascript
const ve = require('./src/config/validateEnv');

ve.validateEnv(); // Throws if missing
const config = ve.getConfig(); // { adminToken, nodeEnv }
```

---

### Logging Modules

#### `auditLog.js`
**Purpose:** Structured audit logging  
**Key Functions:**
- `auditLog({...})` → Create log entry
- `securityEvent(action, details)` → Security event
- `hashForLog(token)` → Safe token format

**Usage:**
```javascript
const al = require('./src/logging/auditLog');

al.auditLog({
  action: al.ACTION.ADMIN_TOKEN_USED,
  level: al.LOG_LEVEL.SECURITY,
  actor: "admin",
  resource: "wallet-update",
  status: "success"
});
```

---

#### `securityAudit.js`
**Purpose:** Security event logging  
**Key Functions:**
- `auditLog(event, details)` → Log event
- `logAuth(success, reason, ip)` → Auth event
- `logSession(event, sessionId, ip)` → Session event
- `logAdminWrite(op, success, wallet, ip)` → Admin write
- `logInjectionBlocked(reason, ip)` → Block event

**Usage:**
```javascript
const sa = require('./src/logging/securityAudit');

sa.logAuth(true, undefined, request.headers.get('CF-Connecting-IP'));
sa.logAdminWrite("update-balance", true, walletAddr, clientIP);
```

---

## 🎯 Common Workflows

### Workflow 1: Admin Authentication
```javascript
// 1. Validate admin token
const authResult = adminAuth.validateAdminToken(token);
if (!authResult.authorized) {
  return authResult.response;
}

// 2. Create session
const session = sessionTokens.createSession(enterpriseId);

// 3. Issue one-time token
const tokenData = sessionTokens.issueOneTimeToken(session.sessionId);

// 4. Return to client
return { sessionId: session.sessionId, token: tokenData.token };
```

---

### Workflow 2: Admin Operation
```javascript
// 1. Validate session
const sessionValid = sessionTokens.validateSession(sessionId);
if (!sessionValid.valid) {
  return sessionTokens.unauthorizedResponse(sessionValid.reason);
}

// 2. Validate admin token from headers
const tokenValid = apiSecurity.validateAdminToken(request);
if (!tokenValid.valid) {
  return tokenValid.response;
}

// 3. Rate limit check
const rateLimit = apiSecurity.applyRateLimit(clientIP);
if (rateLimit.limited) {
  return rateLimit.response;
}

// 4. Sanitize input
const cleanBody = contentSanitizer.sanitizeObject(request.body);

// 5. Check for injection
const injectionCheck = llmProtection.scanRequestBody(cleanBody);
if (!injectionCheck.safe) {
  return llmProtection.injectionBlockedResponse();
}

// 6. Process operation
// ... perform actual operation ...

// 7. Log operation
auditLog.auditLog({
  action: auditLog.ACTION.ADMIN_TOKEN_USED,
  status: "success"
});

// 8. Return with security headers
return sh.secureJsonResponse({ success: true });
```

---

### Workflow 3: Wallet Address Validation
```javascript
const wallet = contentSanitizer.sanitizeWalletAddress(userInput);

if (!wallet.valid) {
  return Response.json({ error: "Invalid wallet address" }, { status: 400 });
}

// Use wallet.address (already validated & normalized)
await updateWallet(wallet.address);
```

---

### Workflow 4: LLM Integration
```javascript
// 1. Filter user input
const filtered = llmSafetyFilter.filterLLMInput(userMessage);
if (!filtered.safe) {
  return Response.json({ error: filtered.reason }, { status: 400 });
}

// 2. Call LLM with filtered input
const response = await callClaude(filtered.sanitized);

// 3. Filter output (redact secrets)
const cleanResponse = llmSafetyFilter.filterLLMOutput(response);

// 4. Return to user
return Response.json({ response: cleanResponse });
```

---

## 🐛 Error Code Reference

### Session Errors
| Code | Message | Meaning |
|------|---------|---------|
| `SESSION_NOT_FOUND` | Session not found or expired | Session doesn't exist |
| `SESSION_EXPIRED` | Session expired | Session TTL exceeded |
| `NO_ACTIVE_SESSION` | No active session | No session for this store |
| `INVALID_SESSION_TOKEN` | Invalid session token | Token doesn't match |

### Token Errors
| Code | Message | Meaning |
|------|---------|---------|
| `NO_VALID_TOKEN` | No valid token for this session | Token was already used |
| `TOKEN_EXPIRED` | One-time token expired | Token TTL exceeded |
| `INVALID_TOKEN` | Invalid token | Hash doesn't match |
| `TOKEN_REQUIRED` | Token required | Empty/null token |

### Auth Errors
| Code | Message | Meaning |
|------|---------|---------|
| `UNAUTHORIZED` | Unauthorized | Invalid credentials |
| `NOT_CONFIGURED` | Admin token not configured | Missing env var |
| `FORBIDDEN` | Forbidden: enterprise administrator access required | Non-admin user |

### Security Errors
| Code | Message | Meaning |
|------|---------|---------|
| `INJECTION_DETECTED` | Invalid input detected. Request blocked. | Malicious pattern found |
| `RATE_LIMITED` | Too many requests. Please try again later. | Rate limit exceeded |
| `INVALID_INPUT` | Invalid request input | Malformed body |

---

## 🔐 Security Best Practices

### ✅ DO
- ✅ Always validate environment variables on startup
- ✅ Always sanitize user input before processing
- ✅ Always check session validity before operations
- ✅ Always use timing-safe token comparisons
- ✅ Always log security events
- ✅ Always set security headers
- ✅ Always clean up expired sessions

### ❌ DON'T
- ❌ Don't log token values
- ❌ Don't bypass rate limiting
- ❌ Don't store plaintext passwords
- ❌ Don't trust user input
- ❌ Don't use in-memory stores in production
- ❌ Don't skip HTTPS in production
- ❌ Don't expose error details to clients

---

## 📚 Example Netlify Function

```javascript
import { createSession } from './src/auth/sessionTokens.js';
import { sanitizeObject } from './src/security/contentSanitizer.js';
import { validateAdminToken } from './src/middleware/apiSecurity.js';
import { getSecurityHeaders } from './src/config/securityHeaders.js';
import { auditLog, ACTION, LOG_LEVEL } from './src/logging/auditLog.js';

export default async (req, context) => {
  // 1. Validate token
  const token = validateAdminToken(req);
  if (!token.valid) {
    return token.response;
  }

  // 2. Parse and sanitize body
  let body;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), {
      status: 400,
      headers: getSecurityHeaders()
    });
  }

  const cleanBody = sanitizeObject(body);

  // 3. Process request
  try {
    // ... your logic ...

    // 4. Log success
    auditLog({
      action: ACTION.ADMIN_TOKEN_USED,
      level: LOG_LEVEL.SECURITY,
      status: "success"
    });

    // 5. Return secure response
    const headers = getSecurityHeaders();
    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers
    });
  } catch (error) {
    // 6. Log failure
    auditLog({
      action: ACTION.ADMIN_TOKEN_USED,
      level: LOG_LEVEL.ERROR,
      status: "failure",
      reason: error.message
    });

    const headers = getSecurityHeaders();
    return new Response(JSON.stringify({ error: "Internal error" }), {
      status: 500,
      headers
    });
  }
};
```

---

## 🚀 Performance Tips

| Task | Time | Optimization |
|------|------|--------------|
| Token Generation | ~0.1ms | Cache where possible |
| Sanitization | ~1ms | Pre-compile regex patterns |
| Session Creation | ~1ms | Batch operations |
| Rate Limiting | ~0.5ms | Use distributed store |
| Injection Detection | ~2ms | Use simpler patterns first |

---

## 📞 Support

For issues:
1. Check the module documentation
2. Review example workflows
3. Check error code reference
4. See CODEBASE_ANALYSIS.md for detailed info
5. Check CODE_FIXES_GUIDE.md for known issues

---

**Last Updated:** 2026-04-30  
**Version:** 1.0
