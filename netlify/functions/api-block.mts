import type { Config } from "@netlify/functions";
import { secureJson } from "../lib/security.js";

/**
 * Deny non-v2 API routes to prevent accidental data exposure through
 * deprecated or forwarded API paths.
 */
export default async (req: Request) => {
  const url = new URL(req.url);

  return secureJson(
    {
      error: "Deprecated API version. Use /api/v2/*",
      apiVersion: "v2",
    },
    426,
  );
};

export const config: Config = {
  path: "/api/v1/*",
};
