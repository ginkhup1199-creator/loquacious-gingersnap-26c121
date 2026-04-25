import type { Config } from "@netlify/functions";
import { secureJson } from "../lib/security.js";

export default async (_req: Request) => {
  return secureJson(
    {
      status: "ok",
      apiVersion: "v2",
    },
    200,
    false,
  );
};

export const config: Config = {
  path: "/api/v2/health",
  method: ["GET"],
};
