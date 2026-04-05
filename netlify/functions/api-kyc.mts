import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAdminSession,
  secureJson,
  auditLog,
  getClientIp,
} from "../lib/security.mjs";

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const kyc = await store.get("kyc", { type: "json" });
    return secureJson(
      kyc || { state: "unverified", name: "", docType: "" },
      200,
      true
    );
  }

  if (req.method === "POST") {
    const body = await req.json() as Record<string, unknown>;
    // Only admin can approve/reject; users can submit pending
    if (body.state === "approved" || body.state === "unverified") {
      const sessionResult = await validateAdminSession(req, store);
      if (!sessionResult.valid) {
        auditLog("AUTH_FAILURE", { operation: "update-kyc", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }
      auditLog("ADMIN_WRITE", { operation: "update-kyc", state: body.state, ip });
    }
    await store.setJSON("kyc", body);
    return secureJson(body);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/kyc",
  method: ["GET", "POST"],
};
