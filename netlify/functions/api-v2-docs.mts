import type { Config } from "@netlify/functions";
import { secureJson } from "../lib/security.js";

const ENDPOINTS = [
  { method: "GET", path: "/api/v2/system/version", description: "Build and version metadata" },
  { method: "GET", path: "/api/v2/system/health", description: "Detailed v2 health status" },
  { method: "GET", path: "/api/v2/status", description: "Deployment status" },
  { method: "GET", path: "/api/v2/docs", description: "API v2 documentation index" },
  { method: "GET", path: "/api/v2/health", description: "Legacy health endpoint under v2 path" },
];

export default async (_req: Request) => {
  return secureJson(
    {
      title: "NexusTrade API v2",
      version: "v2",
      docs: "/docs/API_V2_REFERENCE.md",
      endpoints: ENDPOINTS,
    },
    200,
    false,
  );
};

export const config: Config = {
  path: "/api/v2/docs",
  method: ["GET"],
};
