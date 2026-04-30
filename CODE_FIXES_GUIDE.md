# NexusTrade Code Fixes & Implementation Guide

**Generated:** 2026-04-30

---

## 🔧 Recommended Code Fixes

### Fix #1: Add Depth Limiting to Recursive Sanitization

**File:** `src/security/contentSanitizer.js`

**Problem:** Deeply nested objects could cause stack overflow or performance issues.

**Before:**
```javascript
function sanitizeObject(data, options = {}) {
  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === "string") {
    return sanitizeString(data, options);
  }

  if (typeof data === "number" || typeof data === "boolean") {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map((item) => sanitizeObject(item, options));
  }

  if (typeof data === "object") {
    const result = {};
    for (const key of Object.keys(data)) {
      const safeKey = sanitizeString(key, { maxLength: 64, escapeHtmlChars: false });
      if (safeKey) {
        result[safeKey] = sanitizeObject(data[key], options);
      }
    }
    return result;
  }

  return undefined;
}
```

**After:**
```javascript
const MAX_NESTING_DEPTH = 50;

function sanitizeObject(data, options = {}, depth = 0) {
  // Prevent stack overflow from deeply nested structures
  if (depth > MAX_NESTING_DEPTH) {
    return undefined;
  }

  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === "string") {
    return sanitizeString(data, options);
  }

  if (typeof data === "number" || typeof data === "boolean") {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map((item) => sanitizeObject(item, options, depth + 1));
  }

  if (typeof data === "object") {
    const result = {};
    for (const key of Object.keys(data)) {
      const safeKey = sanitizeString(key, { maxLength: 64, escapeHtmlChars: false });
      if (safeKey) {
        result[safeKey] = sanitizeObject(data[key], options, depth + 1);
      }
    }
    return result;
  }

  return undefined;
}
```

---

### Fix #2: Add Input Length Validation to Token Comparison

**File:** `src/auth/sessionTokens.js`

**Problem:** Token format validation before comparison adds defense-in-depth.

**Before:**
```javascript
function validateAndConsumeToken(sessionId, token) {
  const session = activeSessions.get(sessionId);

  if (!session) {
    return { valid: false, reason: "Session not found or expired" };
  }

  const now = Date.now();
  if (now > session.expiresAt) {
    activeSessions.delete(sessionId);
    return { valid: false, reason: "Session expired" };
  }

  if (!session.oneTimeToken || session.tokenUsed) {
    return { valid: false, reason: "No valid token for this session. Request a new token." };
  }

  if (now > session.tokenExpiresAt) {
    session.tokenUsed = true;
    return { valid: false, reason: "One-time token expired. Request a new token." };
  }

  if (typeof token !== "string" || token.length === 0) {
    return { valid: false, reason: "Token required" };
  }

  // Hash the provided token and compare to stored hash
  const providedHash = crypto.createHash("sha256").update(token).digest("hex");
  let tokensMatch = false;
  try {
    const storedBuf = Buffer.from(session.oneTimeToken, "hex");
    const providedBuf = Buffer.from(providedHash, "hex");
    tokensMatch =
      storedBuf.length === providedBuf.length &&
      crypto.timingSafeEqual(storedBuf, providedBuf);
  } catch {
    tokensMatch = false;
  }

  if (!tokensMatch) {
    return { valid: false, reason: "Invalid token" };
  }

  session.tokenUsed = true;
  session.oneTimeToken = null;

  return { valid: true, enterpriseId: session.enterpriseId };
}
```

**After:**
```javascript
function validateAndConsumeToken(sessionId, token) {
  const session = activeSessions.get(sessionId);

  if (!session) {
    return { valid: false, reason: "Session not found or expired" };
  }

  const now = Date.now();
  if (now > session.expiresAt) {
    activeSessions.delete(sessionId);
    return { valid: false, reason: "Session expired" };
  }

  if (!session.oneTimeToken || session.tokenUsed) {
    return { valid: false, reason: "No valid token for this session. Request a new token." };
  }

  if (now > session.tokenExpiresAt) {
    session.tokenUsed = true;
    return { valid: false, reason: "One-time token expired. Request a new token." };
  }

  if (typeof token !== "string" || token.length === 0) {
    return { valid: false, reason: "Token required" };
  }

  // Validate token format (64 hex chars for 32 bytes)
  if (token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) {
    return { valid: false, reason: "Invalid token format" };
  }

  // Hash the provided token and compare to stored hash
  const providedHash = crypto.createHash("sha256").update(token).digest("hex");
  let tokensMatch = false;
  try {
    const storedBuf = Buffer.from(session.oneTimeToken, "hex");
    const providedBuf = Buffer.from(providedHash, "hex");
    tokensMatch =
      storedBuf.length === providedBuf.length &&
      crypto.timingSafeEqual(storedBuf, providedBuf);
  } catch {
    tokensMatch = false;
  }

  if (!tokensMatch) {
    return { valid: false, reason: "Invalid token" };
  }

  session.tokenUsed = true;
  session.oneTimeToken = null;

  return { valid: true, enterpriseId: session.enterpriseId };
}
```

---

### Fix #3: Add Try-Catch to Async Session Operations

**File:** `src/auth/sessionManager.js`

**Problem:** Store operations could fail silently; should add error handling.

**Before:**
```javascript
async function createSession(store) {
  const sessionId = generateSessionId();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

  const session = {
    sessionId,
    expiresAt,
    createdAt: new Date().toISOString(),
    usedAt: null,
  };

  await store.setJSON(SESSION_STORE_KEY, session);
  return { sessionId, expiresAt };
}
```

**After:**
```javascript
async function createSession(store) {
  const sessionId = generateSessionId();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

  const session = {
    sessionId,
    expiresAt,
    createdAt: new Date().toISOString(),
    usedAt: null,
  };

  try {
    await store.setJSON(SESSION_STORE_KEY, session);
    return { sessionId, expiresAt };
  } catch (error) {
    console.error("[SessionManager] Failed to create session:", error.message);
    throw new Error("Failed to create admin session. Please try again.");
  }
}

async function validateSession(store, sessionId) {
  if (!sessionId || typeof sessionId !== "string") {
    return { valid: false, reason: "No session token provided" };
  }

  try {
    const session = await store.get(SESSION_STORE_KEY, { type: "json" });

    if (!session) {
      return { valid: false, reason: "No active session" };
    }

    if (session.sessionId !== sessionId) {
      return { valid: false, reason: "Invalid session token" };
    }

    if (new Date(session.expiresAt).getTime() < Date.now()) {
      await store.delete(SESSION_STORE_KEY);
      return { valid: false, reason: "Session expired" };
    }

    return { valid: true, session };
  } catch (error) {
    console.error("[SessionManager] Failed to validate session:", error.message);
    return { valid: false, reason: "Session validation failed" };
  }
}
```

---

### Fix #4: Implement Distributed Rate Limiting

**File:** `src/middleware/apiSecurity.js` (NEW ADDITION)

**Problem:** Current rate limiting is per-instance; doesn't work in distributed environments.

**Add New Function:**
```javascript
/**
 * Distributed rate limiter using an external store (Redis, Netlify KV, etc.)
 * @param {object} store - A persistent store instance (Redis, KV, etc.)
 * @param {string} ip - The client IP address.
 * @param {object} options - Configuration options.
 * @returns {Promise<boolean>} True if rate limited.
 */
async function isRateLimitedAsync(store, ip, options = {}) {
  const windowMs = options.windowMs || RATE_LIMIT_WINDOW_MS;
  const maxRequests = options.maxRequests || RATE_LIMIT_MAX_REQUESTS;
  const key = `ratelimit:${ip}`;

  try {
    const current = await store.get(key);

    if (!current) {
      await store.set(key, { count: 1, expires: Date.now() + windowMs }, { 
        expiry: windowMs / 1000 
      });
      return false;
    }

    const data = typeof current === "string" ? JSON.parse(current) : current;

    if (data.expires < Date.now()) {
      await store.set(key, { count: 1, expires: Date.now() + windowMs }, { 
        expiry: windowMs / 1000 
      });
      return false;
    }

    data.count += 1;
    if (data.count > maxRequests) {
      return true;
    }

    await store.set(key, data, { expiry: windowMs / 1000 });
    return false;
  } catch (error) {
    console.error("[RateLimit] Error checking distributed rate limit:", error.message);
    // Fail open to prevent service outage
    return false;
  }
}

/**
 * Apply distributed rate limiting for a given client IP.
 * @param {object} store - A persistent store instance.
 * @param {string} ip - The client IP address.
 * @returns {Promise<{limited: boolean, response?: Response}>}
 */
async function applyRateLimitAsync(store, ip) {
  if (await isRateLimitedAsync(store, ip)) {
    return {
      limited: true,
      response: Response.json(
        { error: "Too many requests. Please try again later." },
        { status: 429 }
      ),
    };
  }
  return { limited: false };
}

module.exports = { 
  validateAdminToken, 
  applyRateLimit, 
  validateRequestBody,
  isRateLimitedAsync,
  applyRateLimitAsync
};
```

---

### Fix #5: Add Session Fingerprinting

**File:** `src/auth/sessionTokens.js` (ENHANCEMENT)

**Problem:** Sessions could be hijacked if tokens leak; fingerprinting adds protection.

**Add New Functions:**
```javascript
const crypto = require("crypto");

/**
 * Creates a fingerprint hash from client properties.
 * @param {string} ip - Client IP address
 * @param {string} userAgent - Client User-Agent header
 * @returns {string} Fingerprint hash
 */
function createFingerprint(ip, userAgent) {
  const input = `${ip}:${userAgent}`;
  return crypto.createHash("sha256").update(input).digest("hex");
}

/**
 * Creates a new admin session with fingerprinting.
 * @param {string} enterpriseId - Enterprise identifier
 * @param {string} ip - Client IP address
 * @param {string} userAgent - Client User-Agent header
 * @returns {{ sessionId, expiresAt, fingerprint }}
 */
function createSessionWithFingerprint(enterpriseId, ip, userAgent) {
  const sessionId = generateSecureToken(24);
  const now = Date.now();
  const fingerprint = createFingerprint(ip, userAgent);

  activeSessions.set(sessionId, {
    enterpriseId,
    fingerprint,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
    oneTimeToken: null,
    tokenExpiresAt: null,
    tokenUsed: true,
  });

  return {
    sessionId,
    expiresAt: new Date(now + SESSION_TTL_MS).toISOString(),
    fingerprint: fingerprint.slice(0, 16) + "...", // Return partial for client
  };
}

/**
 * Validates a session with fingerprint verification.
 * @param {string} sessionId - Session ID
 * @param {string} ip - Client IP
 * @param {string} userAgent - Client User-Agent
 * @returns {{ valid: boolean, reason?: string }}
 */
function validateSessionWithFingerprint(sessionId, ip, userAgent) {
  const session = activeSessions.get(sessionId);

  if (!session) {
    return { valid: false, reason: "Session not found" };
  }

  const now = Date.now();
  if (now > session.expiresAt) {
    activeSessions.delete(sessionId);
    return { valid: false, reason: "Session expired" };
  }

  const currentFingerprint = createFingerprint(ip, userAgent);
  if (session.fingerprint !== currentFingerprint) {
    return { valid: false, reason: "Session fingerprint mismatch. Possible session hijacking." };
  }

  return { valid: true };
}
```

---

## 🚀 Implementation Guide

### Step 1: Apply Depth Limiting Fix
```bash
# Edit contentSanitizer.js
# Change sanitizeObject to accept depth parameter
# Update MAX_NESTING_DEPTH constant
# Test with deeply nested objects
```

### Step 2: Add Token Format Validation
```bash
# Edit sessionTokens.js
# Add format validation in validateAndConsumeToken
# Add regex pattern test for hex format
# Test with invalid token formats
```

### Step 3: Add Error Handling to Async Operations
```bash
# Edit sessionManager.js
# Wrap store operations in try-catch
# Add console.error logging
# Test with store failures
```

### Step 4: Implement Distributed Rate Limiting (Production)
```bash
# Choose store: Redis, Netlify KV, or other
# Import store client in apiSecurity.js
# Add isRateLimitedAsync and applyRateLimitAsync
# Update endpoint handlers to use async versions
# Test with multiple function instances
```

### Step 5: Add Session Fingerprinting
```bash
# Edit sessionTokens.js
# Add createFingerprint and new session functions
# Pass IP and User-Agent in session creation
# Validate fingerprint on each request
# Test with different clients
```

---

## ✅ Testing Checklist

### Security Tests
- [ ] Test with malicious injection patterns
- [ ] Test with oversized inputs
- [ ] Test with deeply nested objects
- [ ] Test with invalid token formats
- [ ] Test rate limiting with concurrent requests
- [ ] Test session expiration edge cases
- [ ] Test session hijacking prevention

### Error Handling Tests
- [ ] Test with store failures
- [ ] Test with invalid session IDs
- [ ] Test with expired tokens
- [ ] Test with missing environment variables
- [ ] Test with invalid request bodies

### Performance Tests
- [ ] Test recursive sanitization speed
- [ ] Test rate limiting overhead
- [ ] Test session cleanup efficiency
- [ ] Test token generation performance

### Integration Tests
- [ ] Test full auth flow
- [ ] Test with actual Netlify Functions
- [ ] Test with different HTTP clients
- [ ] Test with edge cases

---

## 📊 Metrics to Track

```javascript
// Add to logging modules
const metrics = {
  tokenGenerationTime: 0,
  sanitizationTime: 0,
  rateLimitCheckTime: 0,
  sessionValidationTime: 0,
  injectionDetectionTime: 0,
};

// Example instrumentation:
const start = Date.now();
const token = generateSecureToken();
metrics.tokenGenerationTime = Date.now() - start;
```

---

## 🔐 Security Checklist

- [ ] All tokens use cryptographically secure generation
- [ ] All comparisons use timing-safe functions
- [ ] All inputs are validated before processing
- [ ] All outputs are sanitized before returning
- [ ] All sessions have expiration times
- [ ] All errors avoid information leakage
- [ ] All logging omits sensitive values
- [ ] All rate limiting is distributed
- [ ] All sessions support fingerprinting
- [ ] All CSRF tokens are validated

---

## 📝 Documentation Updates

Add to relevant modules:

```javascript
/**
 * Usage example for the new depth-limiting sanitizeObject:
 *
 * const data = { a: { b: { c: { /* ... */ } } } };
 * const clean = sanitizeObject(data, {}, 0);
 * // Returns undefined if nesting exceeds MAX_NESTING_DEPTH
 */
```

---

## Version Control

When applying fixes:
1. Create feature branch: `git checkout -b fix/security-enhancements`
2. Apply fixes one at a time
3. Test thoroughly after each fix
4. Commit with clear messages:
   ```bash
   git commit -m "fix: add depth limiting to recursive sanitization
   
   - Prevents stack overflow from deeply nested objects
   - Adds MAX_NESTING_DEPTH constant
   - Maintains backward compatibility
   - Fixes #123"
   ```

---

## Deployment Strategy

1. **Development:** Apply and test all fixes
2. **Staging:** Deploy with enhanced logging
3. **Monitoring:** Watch metrics for 48 hours
4. **Production:** Gradual rollout (canary)
5. **Rollback:** Keep previous version available

---

**Last Updated:** 2026-04-30  
**Status:** Ready for Implementation
