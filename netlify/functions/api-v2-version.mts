import type { Config } from "@netlify/functions";
import { secureJson } from "../lib/security.js";
import type { ApiVersionInfo } from "../lib/types.js";

export default async (_req: Request) => {
  const payload: ApiVersionInfo = {
    apiVersion: "v2",
    appVersion: process.env.APP_VERSION ?? process.env.npm_package_version ?? "unknown",
    commitRef: process.env.COMMIT_REF ?? "unknown",
    deployId: process.env.DEPLOY_ID ?? "unknown",
    timestamp: new Date().toISOString(),
  };

  return secureJson(payload, 200, false);
};

export const config: Config = {
  path: "/api/v2/system/version",
  method: ["GET"],
};
