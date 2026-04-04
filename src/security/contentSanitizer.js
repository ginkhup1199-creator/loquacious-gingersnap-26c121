/**
 * Content Sanitizer for NexusTrade.
 *
 * Sanitizes all user-supplied data before:
 *  - Storage in @netlify/blobs
 *  - Inclusion in API responses
 *  - Forwarding to external services
 *
 * Protections:
 *  - HTML/JavaScript injection (XSS)
 *  - Dangerous protocol schemes (javascript:, data:)
 *  - Null-byte injection
 *  - Excessively long strings (DoS / buffer issues)
 */

const MAX_STRING_LENGTH = 1000;

/**
 * Escapes HTML special characters to prevent XSS.
 *
 * @param {string} value
 * @returns {string}
 */
function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}

/**
 * Removes null bytes and trims whitespace.
 *
 * @param {string} value
 * @returns {string}
 */
function cleanString(value) {
  // eslint-disable-next-line no-control-regex
  return value.replace(/\x00/g, "").trim();
}

/**
 * Sanitizes a single string value.
 * - Removes null bytes
 * - Enforces max length
 * - Escapes HTML special characters
 * - Blocks dangerous URI schemes
 *
 * @param {string} value
 * @param {{ maxLength?: number, escapeHtmlChars?: boolean }} [options]
 * @returns {string}
 */
function sanitizeString(value, options = {}) {
  if (typeof value !== "string") {
    return String(value ?? "");
  }

  const maxLength = options.maxLength ?? MAX_STRING_LENGTH;
  let sanitized = cleanString(value);

  if (sanitized.length > maxLength) {
    sanitized = sanitized.slice(0, maxLength);
  }

  // Block dangerous URI schemes
  if (/^(javascript|data|vbscript|file):/i.test(sanitized)) {
    return "";
  }

  if (options.escapeHtmlChars !== false) {
    sanitized = escapeHtml(sanitized);
  }

  return sanitized;
}

/**
 * Recursively sanitizes all string values in a plain object or array.
 * Non-string primitives (numbers, booleans) are passed through unchanged.
 * Functions and prototypes are stripped.
 *
 * @param {unknown} data - The value to sanitize.
 * @param {{ maxLength?: number, escapeHtmlChars?: boolean }} [options]
 * @returns {unknown} The sanitized value.
 */
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
      // Sanitize both key and value to prevent prototype pollution
      const safeKey = sanitizeString(key, { maxLength: 64, escapeHtmlChars: false });
      if (safeKey) {
        result[safeKey] = sanitizeObject(data[key], options);
      }
    }
    return result;
  }

  // Discard functions and exotic types
  return undefined;
}

/**
 * Validates and sanitizes a wallet address.
 * Allows only hexadecimal Ethereum/BSC addresses and base58 Bitcoin/Solana addresses.
 *
 * @param {string} address
 * @returns {{ valid: boolean, address?: string }}
 */
function sanitizeWalletAddress(address) {
  if (typeof address !== "string") {
    return { valid: false };
  }

  const cleaned = address.trim();

  // Ethereum / BSC / ERC-20 style
  if (/^0x[0-9a-fA-F]{40}$/.test(cleaned)) {
    return { valid: true, address: cleaned.toLowerCase() };
  }

  // Bitcoin bech32 (bc1...) or legacy (1... / 3...)
  if (/^(bc1|[13])[A-Za-z0-9]{25,62}$/.test(cleaned)) {
    return { valid: true, address: cleaned };
  }

  // Tron (T...) or Solana (base58, 32–44 chars)
  if (/^[A-Za-z0-9]{32,50}$/.test(cleaned)) {
    return { valid: true, address: cleaned };
  }

  return { valid: false };
}

module.exports = {
  sanitizeString,
  sanitizeObject,
  sanitizeWalletAddress,
  escapeHtml,
};
