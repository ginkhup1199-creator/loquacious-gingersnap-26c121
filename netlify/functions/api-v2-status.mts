import type { Config } from "@netlify/functions";
import { secureJson } from "../lib/security.js";
import type { ApiStatusInfo } from "../lib/types.js";

export default async (_req: Request) => {
  const payload: ApiStatusInfo = {
    status: "ok",
    apiVersion: "v2",
    environment: process.env.CONTEXT ?? process.env.NODE_ENV ?? "production",
    timestamp: new Date().toISOString(),
  };

  return secureJson(payload, 200, false);
};

export const config: Config = {
  path: "/api/v2/status",
  method: ["GET"],
};
