import type { Config } from "@netlify/functions";
import { secureJson } from "../lib/security.js";

const VERSION = "1.0.0";

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
