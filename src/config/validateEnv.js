/**
 * Environment variable validation module.
 * Call this at application startup to ensure all required variables are set.
 */

const REQUIRED_ENV_VARS = ["ADMIN_TOKEN"];

/**
 * Validates that all required environment variables are present.
 * Throws an error if any required variable is missing.
 */
function validateEnv() {
  const missing = REQUIRED_ENV_VARS.filter((key) => !process.env[key]);

  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}. ` +
        "Set them in Netlify: Site Settings -> Build & Deploy -> Environment Variables."
    );
  }

  const adminToken = process.env.ADMIN_TOKEN;
  if (adminToken && adminToken.length < 32) {
    throw new Error(
      "ADMIN_TOKEN must be at least 32 characters long for security."
    );
  }
}

/**
 * Returns validated configuration values from environment variables.
 */
function getConfig() {
  validateEnv();
  return {
    adminToken: process.env.ADMIN_TOKEN,
    nodeEnv: process.env.NODE_ENV || "development",
  };
}

module.exports = { validateEnv, getConfig };
