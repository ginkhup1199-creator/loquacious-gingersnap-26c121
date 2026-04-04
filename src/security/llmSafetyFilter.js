/**
 * LLM / AI Prompt-Injection Safety Filter for NexusTrade.
 *
 * Protects against attacks that attempt to:
 *  - Override system prompts or inject new instructions (prompt injection)
 *  - Exfiltrate secrets, environment variables, or tokens via LLM output
 *  - Escape conversation context to issue OS/tool commands
 *  - Abuse function-calling / tool-use features of AI APIs
 *  - Perform indirect prompt injection via user-supplied content sent to an LLM
 *
 * Usage:
 *   const { filterLLMInput, filterLLMOutput } = require('./llmSafetyFilter');
 *   const { safe, reason } = filterLLMInput(userMessage);
 *   if (!safe) return reject(reason);
 *   const response = await callLLM(userMessage);
 *   const cleanResponse = filterLLMOutput(response);
 */

// ---------------------------------------------------------------------------
// Patterns that indicate prompt-injection attempts in user input
// ---------------------------------------------------------------------------
const INJECTION_PATTERNS = [
  // System-prompt override attempts
  /\bignore\s+(all\s+)?previous\s+instructions?\b/i,
  /\bforget\s+(all\s+)?previous\s+instructions?\b/i,
  /\bdisregard\s+(all\s+)?previous\s+instructions?\b/i,
  /\boverride\s+(system\s+)?prompt\b/i,
  /\bnew\s+instructions?:/i,
  /\bsystem\s*:\s*you\s+are\b/i,
  /\byou\s+are\s+now\b.{0,60}\bassistant\b/i,
  /\bact\s+as\b.{0,40}\b(admin|root|system|superuser)\b/i,

  // Context-escape and role-play exploits
  /\bdan\s+mode\b/i,
  /\bjailbreak\b/i,
  /\bdev\s+mode\b/i,
  /\bgrandma\s+trick\b/i,
  /\bpretend\s+you\s+(have\s+no|don'?t\s+have)\s+(restrictions?|limitations?|rules?)\b/i,
  /\byou\s+(have\s+no|don'?t\s+have)\s+(restrictions?|limitations?|rules?)\b/i,

  // Token / secret exfiltration
  /\bprint\s+(your\s+)?(system\s+)?prompt\b/i,
  /\brepeat\s+(your\s+)?initial\s+instructions?\b/i,
  /\bshow\s+(me\s+)?(your\s+)?(secret|api[_\s]?key|token|password|credential|env)\b/i,
  /\bwhat\s+(is|are)\s+(your\s+)?(api[_\s]?key|token|secret|password|admin)\b/i,
  /process\.env/i,
  /ADMIN_TOKEN/i,
  /\.env\b/i,

  // Function / tool calling exploits
  /\bcall\s+(function|tool)\s*\(/i,
  /\bexecute\s+(command|script|code|function)\b/i,
  /\brun\s+(shell|bash|cmd|powershell|python|node)\b/i,
  /\beval\s*\(/i,

  // Indirect injection delimiters (common separator tricks)
  /------+\s*system\s*------+/i,
  /###\s*system\s*###/i,
  /\[system\]/i,
  /<\s*system\s*>/i,
];

// ---------------------------------------------------------------------------
// Patterns that should never appear in LLM output (secret leakage guard)
// ---------------------------------------------------------------------------
const OUTPUT_SENSITIVE_PATTERNS = [
  // Looks like a generic secret/key
  /\b[A-Za-z0-9+/]{32,}={0,2}\b/, // base64-like strings
  /\bsk[-_][a-zA-Z0-9]{20,}\b/, // OpenAI-style secret keys
  /\bghp_[A-Za-z0-9]{36}\b/, // GitHub Personal Access Tokens
  /process\.env\./,
  /ADMIN_TOKEN\s*[:=]/i,
  /password\s*[:=]\s*\S+/i,
];

const REDACT_PLACEHOLDER = "[REDACTED]";

/**
 * Checks user-supplied input for known prompt-injection patterns before
 * the content is forwarded to any LLM API.
 *
 * @param {string} input - Raw user input.
 * @returns {{ safe: boolean, reason?: string, sanitized?: string }}
 */
function filterLLMInput(input) {
  if (typeof input !== "string") {
    return { safe: false, reason: "Input must be a string" };
  }

  const trimmed = input.trim();

  if (trimmed.length === 0) {
    return { safe: true, sanitized: trimmed };
  }

  if (trimmed.length > 4000) {
    return { safe: false, reason: "Input exceeds maximum allowed length" };
  }

  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(trimmed)) {
      return {
        safe: false,
        reason: "Input contains a disallowed pattern and cannot be processed",
      };
    }
  }

  return { safe: true, sanitized: trimmed };
}

/**
 * Scans LLM output for sensitive data patterns and redacts them.
 * This is a defense-in-depth measure for output returned to clients.
 *
 * @param {string} output - Raw LLM response text.
 * @returns {string} The output with sensitive patterns replaced by [REDACTED].
 */
function filterLLMOutput(output) {
  if (typeof output !== "string") return output;

  let sanitized = output;
  for (const pattern of OUTPUT_SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(new RegExp(pattern.source, pattern.flags + "g"), REDACT_PLACEHOLDER);
  }
  return sanitized;
}

/**
 * Returns true if the string contains any known injection pattern.
 * Useful for quick guard checks without needing the full result object.
 *
 * @param {string} input
 * @returns {boolean}
 */
function containsInjectionPattern(input) {
  return !filterLLMInput(input).safe;
}

module.exports = { filterLLMInput, filterLLMOutput, containsInjectionPattern };
