import type { Config } from "@netlify/functions";
import { secureJson } from "../lib/security.js";

/**
 * Single-master security policy:
 * sub-admin accounts are disabled and only one master account is allowed.
 */
export default async () => {
  return secureJson(
    {
      error: "Sub-admin accounts are disabled. Only one master account is allowed.",
      policy: "single-master-only",
    },
    403,
  );
};

export const config: Config = {
  path: "/api/v2/admin-accounts",
  method: ["GET", "POST", "DELETE"],
};
