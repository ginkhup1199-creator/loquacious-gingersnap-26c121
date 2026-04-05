import type { Config } from "@netlify/functions";
import { secureJson } from "../lib/security.js";

const VERSION =
  process.env.APP_VERSION ??
  process.env.npm_package_version ??
  process.env.COMMIT_REF ??
  process.env.DEPLOY_ID ??
  "unknown";

export default async (_req: Request) => {
  return secureJson(
    {
      status: "ok",
      version: VERSION,
      timestamp: new Date().toISOString(),
    },
    200,
    false,
  );
};

export const config: Config = {
  path: "/api/health",
  method: ["GET"],
};
