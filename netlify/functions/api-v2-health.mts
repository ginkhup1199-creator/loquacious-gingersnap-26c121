import type { Config } from "@netlify/functions";
import { secureJson } from "../lib/security.js";
import type { ApiHealthInfo } from "../lib/types.js";

export default async (_req: Request) => {
  const payload: ApiHealthInfo = {
    status: "ok",
    apiVersion: "v2",
    timestamp: new Date().toISOString(),
  };

  return secureJson(payload, 200, false);
};

export const config: Config = {
  path: "/api/v2/system/health",
  method: ["GET"],
};
