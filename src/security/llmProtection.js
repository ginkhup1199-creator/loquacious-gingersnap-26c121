/**
 * LLM/Prompt Injection Protection Module for NexusTrade.
 * Detects and neutralizes prompt injection attacks, data exfiltration
 * attempts, and malicious AI instruction payloads in user input.
 */

// Patterns commonly used in prompt injection and LLM manipulation attacks
const INJECTION_PATTERNS = [
  // Direct instruction injection
  /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directives?)/i,
  /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i,
  /forget\s+(all\s+)?(previous|your)\s+(instructions?|prompts?|rules?|training)/i,
  /override\s+(all\s+)?(previous|prior|safety|system)\s+(instructions?|prompts?|rules?|settings?)/i,
  /new\s+(instructions?|directives?|rules?)\s*:/i,
  /system\s*:\s*(ignore|override|forget|disregard)/i,

  // Role play / persona hijacking
  /you\s+are\s+now\s+(a|an)\s+(different|evil|unfiltered|unrestricted|jailbroken)/i,
  /act\s+as\s+(a|an)\s+(different|evil|unrestricted|jailbroken|DAN|unlimited)/i,
  /pretend\s+(you\s+are|to\s+be)\s+(a|an)\s+(different|unrestricted|jailbroken)/i,
  /\[INST\]|\[\/INST\]|<\|system\|>|<\|user\|>|<\|assistant\|>/i,

  // Data exfiltration patterns
  /reveal\s+(all|your|the)\s+(secret|hidden|internal|system|api|admin)\s+(data|key|token|password|config)/i,
  /output\s+(all|the)\s+(database|user|wallet|admin|secret|hidden)\s+(data|records?|entries?|information)/i,
  /dump\s+(all|the)\s+(database|user|wallet|data|records?)/i,
  /print\s+(all|the)\s+(secret|hidden|internal|api|admin)\s+(key|token|password|data)/i,
  /show\s+me\s+(all|the)\s+(database|user|wallet|admin|secret)\s+(data|records?|passwords?)/i,

  // Injection via special delimiters
  /---\s*(new\s+)?prompt|={3,}\s*(new\s+)?prompt|\|\|\|\s*(new\s+)?instruction/i,
  /<system>|<\/system>|<prompt>|<\/prompt>|<instruction>|<\/instruction>/i,

  // Wallet/financial specific attacks
  /transfer\s+(all|my|user|their)\s+(funds|balance|crypto|bitcoin|ethereum|usdt|wallet)/i,
  /withdraw\s+(all|everything|all\s+funds)\s+to\s+(my\s+)?(wallet|address)/i,
  /send\s+(all|all\s+my|all\s+user)\s+(funds|balance|crypto|tokens)\s+to/i,
];

// Strings that are definitely safe (allow list for short common strings)
const MAX_INPUT_LENGTH = 10000;

/**
 * Checks if a string contains prompt injection or LLM manipulation patterns.
 * @param {string} input - The string to check.
 * @returns {{ safe: boolean, reason?: string }} Result of the check.
 */
function checkForInjection(input) {
  if (typeof input !== "string") {
    return { safe: true };
  }

  if (input.length > MAX_INPUT_LENGTH) {
    return { safe: false, reason: "Input exceeds maximum allowed length" };
  }

  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(input)) {
      return { safe: false, reason: "Potentially malicious input detected" };
    }
  }

  return { safe: true };
}

/**
 * Sanitizes a string by removing or encoding potentially dangerous content.
 * Strips HTML tags using multi-pass removal to prevent nested tag bypass,
 * removes control characters, and truncates to max length.
 * @param {string} input - The string to sanitize.
 * @param {number} [maxLength=500] - Maximum allowed length.
 * @returns {string} The sanitized string.
 */
function sanitizeString(input, maxLength = 500) {
  if (typeof input !== "string") {
    return "";
  }

  let s = input.slice(0, maxLength)
    // Remove null bytes and other control characters (except newline/tab)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .trim();

  // Multi-pass HTML tag removal to prevent nested tag bypass (e.g. <scr<script>ipt>)
  let prev;
  do {
    prev = s;
    s = s.replace(/<[^>]*>/g, "");
  } while (s !== prev);

  // Remove any remaining angle brackets to fully prevent HTML injection
  return s.replace(/[<>]/g, "");
}

/**
 * Deeply scans a request body object for injection patterns in all string values.
 * @param {object} body - The request body to scan.
 * @param {string[]} [fieldsToCheck] - Specific fields to check (checks all strings if omitted).
 * @returns {{ safe: boolean, field?: string, reason?: string }} Scan result.
 */
function scanRequestBody(body, fieldsToCheck) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { safe: true };
  }

  const fields = fieldsToCheck || Object.keys(body);

  for (const field of fields) {
    const value = body[field];
    if (typeof value === "string") {
      const result = checkForInjection(value);
      if (!result.safe) {
        return { safe: false, field, reason: result.reason };
      }
    } else if (typeof value === "object" && value !== null) {
      // Recursively scan nested objects
      const nested = scanRequestBody(value);
      if (!nested.safe) {
        return { safe: false, field: `${field}.${nested.field}`, reason: nested.reason };
      }
    }
  }

  return { safe: true };
}

/**
 * Creates a Response for a blocked injection attempt.
 * @returns {Response} A 400 Bad Request response.
 */
function injectionBlockedResponse() {
  return Response.json(
    { error: "Invalid input detected. Request blocked." },
    { status: 400 }
  );
}

module.exports = {
  checkForInjection,
  sanitizeString,
  scanRequestBody,
  injectionBlockedResponse,
};
