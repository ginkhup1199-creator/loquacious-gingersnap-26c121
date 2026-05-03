import type { Config } from "@netlify/functions";
import { secureJson } from "../lib/security.js";

/**
 * Deny non-v2 API routes to prevent accidental data exposure through
 * deprecated or forwarded API paths.
 */
export default async (req: Request) => {
  const url = new URL(req.url);

  if (url.pathname.startsWith("/api/v2/")) {
    return secureJson({ error: "Not found" }, 404);
  }

  return secureJson(
    {
      error: "Unsupported API version. Use /api/v2/*",
      apiVersion: "v2",
    },
    410,
  );
};

export const config: Config = {
  path: "/api/*",
};
