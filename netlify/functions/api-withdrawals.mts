import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAnyAdminSession,
  hasPermission,
  secureJson,
  sanitizeString,
  auditLog,
  persistAuditLog,
  getClientIp,
  assessWithdrawalRisk,
} from "../lib/security.js";

type WithdrawalStatus = "Pending" | "Approved" | "Rejected" | "Completed" | "Failed";

interface WithdrawalRecord {
  id: number;
  wallet: string;
  coin: string;
  network: string;
  address: string;
  amount: number;
  date: string;
  status: WithdrawalStatus;
  requestedAt: string;
  approvedAt?: string;
  completedAt?: string;
  rejectedAt?: string;
  rejectionReason?: string;
  approvalNote?: string;
  processedBy?: string;
  riskLevel?: "low" | "medium" | "high";
  riskFlags?: string[];
}

export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip = getClientIp(context);

  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  if (req.method === "GET") {
    const url = new URL(req.url);
    const walletParam = url.searchParams.get("wallet");

    if (walletParam) {
      // Return only this user's withdrawals (no auth needed for own wallet)
      const safeWallet = sanitizeString(walletParam, 100).toLowerCase();
      const all = ((await store.get("withdrawals", { type: "json" })) || []) as Array<{ wallet?: string }>;
      const filtered = all.filter((w) => w.wallet === safeWallet);
      return secureJson(filtered, 200, true);
    }

    // No wallet param: admin view (requires session)
    const sessionResult = await validateAnyAdminSession(req, store);
    if (!sessionResult.valid || !hasPermission(sessionResult, "withdrawals")) {
      auditLog("AUTH_FAILURE", { operation: "list-withdrawals", reason: sessionResult.reason, ip });
      return secureJson({ error: "Unauthorized" }, 401);
    }
    const withdrawals = await store.get("withdrawals", { type: "json" });
    return secureJson(withdrawals || [], 200, true);
  }

  if (req.method === "POST") {
    let body: any;
    try {
      body = await req.json();
    } catch {
      return secureJson({ error: "Invalid JSON body" }, 400);
    }
    const { action } = body;

    if (action === "add") {
      const reqWallet = sanitizeString(String(body.wallet ?? ""), 100).toLowerCase();
      const reqAmount = parseFloat(body.amount) || 0;
      const reqCoin = sanitizeString(String(body.coin ?? ""), 20).toUpperCase();

      if (!reqWallet || !reqAmount || reqAmount <= 0) {
        return secureJson({ error: "Invalid withdrawal request" }, 400);
      }

      // Validate user has sufficient balance before allowing withdrawal
      const balance = ((await store.get(`balance-${reqWallet}`, { type: "json" })) || { usdt: 0 }) as { usdt: number; [key: string]: number };
      const coinKey = reqCoin.toLowerCase();
      const available = Number(balance[coinKey] ?? balance.usdt ?? 0);
      if (available < reqAmount) {
        return secureJson({ error: "Insufficient balance" }, 400);
      }

      const existing = ((await store.get("withdrawals", { type: "json" })) || []) as WithdrawalRecord[];
      const requestedAt = new Date().toISOString();
      const risk = await assessWithdrawalRisk(
        { wallet: reqWallet, amount: reqAmount, address: sanitizeString(String(body.address ?? ""), 200) },
        store
      );
      const newWithdrawal: WithdrawalRecord = {
        id: Date.now(),
        wallet: reqWallet,
        coin: reqCoin,
        network: sanitizeString(String(body.network ?? ""), 20),
        address: sanitizeString(String(body.address ?? ""), 200),
        amount: reqAmount,
        date: new Date().toISOString().split("T")[0],
        status: "Pending",
        requestedAt,
        riskLevel: risk.riskLevel,
        riskFlags: risk.riskFlags,
      };
      existing.push(newWithdrawal);
      await store.setJSON("withdrawals", existing);
      await persistAuditLog("USER_WRITE", {
        operation: "withdrawal-request",
        wallet: `${reqWallet.slice(0, 8)}…`,
        coin: reqCoin,
        amount: reqAmount,
        riskLevel: risk.riskLevel,
        riskFlags: risk.riskFlags,
        ip,
      }, store);
      return secureJson(newWithdrawal);
    }

    if (action === "process" || action === "approve" || action === "reject") {
      const sessionResult = await validateAnyAdminSession(req, store);
      if (!sessionResult.valid || !hasPermission(sessionResult, "withdrawals")) {
        auditLog("AUTH_FAILURE", { operation: "process-withdrawal", reason: sessionResult.reason, ip });
        return secureJson({ error: "Unauthorized" }, 401);
      }

      const processedBy = sessionResult.role === "master" ? "master-admin" : (sessionResult.username || "subadmin");
      const statusFromBody = sanitizeString(String(body.status ?? "Completed"), 20);
      let safeStatus: WithdrawalStatus;
      if (action === "approve") {
        safeStatus = "Approved";
      } else if (action === "reject") {
        safeStatus = "Rejected";
      } else {
        const allowedStatuses = new Set<WithdrawalStatus>(["Approved", "Rejected", "Completed", "Failed"]);
        safeStatus = allowedStatuses.has(statusFromBody as WithdrawalStatus) ? statusFromBody as WithdrawalStatus : "Completed";
      }
      const approvalNote = sanitizeString(String(body.approvalNote ?? body.note ?? ""), 300);
      const rejectionReason = sanitizeString(String(body.rejectionReason ?? body.reason ?? body.note ?? ""), 300);

      if (action === "approve" && !approvalNote) {
        return secureJson({ error: "Approval note is required" }, 400);
      }
      if (action === "reject" && !rejectionReason) {
        return secureJson({ error: "Rejection reason is required" }, 400);
      }

      const existing = ((await store.get("withdrawals", { type: "json" })) || []) as WithdrawalRecord[];
      let found = false;
      const now = new Date().toISOString();
      const updated = existing.map((w) => {
        if (w.id !== Number(body.id)) return w;
        found = true;

        const next: WithdrawalRecord = {
          ...w,
          status: safeStatus,
          processedBy,
        };

        if (safeStatus === "Approved") {
          next.approvedAt = now;
          next.approvalNote = approvalNote || "Approved via legacy process action";
          next.rejectionReason = undefined;
          next.rejectedAt = undefined;
        } else if (safeStatus === "Rejected") {
          next.rejectedAt = now;
          next.rejectionReason = rejectionReason || "Rejected via legacy process action";
        } else if (safeStatus === "Completed") {
          next.completedAt = now;
          if (approvalNote) next.approvalNote = approvalNote;
        } else if (safeStatus === "Failed") {
          next.rejectionReason = rejectionReason || sanitizeString(String(body.failureReason ?? "Withdrawal failed"), 300);
        }

        return next;
      });

      if (!found) {
        return secureJson({ error: "Withdrawal not found" }, 404);
      }

      await store.setJSON("withdrawals", updated);
      await persistAuditLog("ADMIN_WRITE", {
        operation: "process-withdrawal",
        withdrawalId: body.id,
        status: safeStatus,
        processedBy,
        approvalNote: approvalNote || undefined,
        rejectionReason: rejectionReason || undefined,
        ip,
      }, store);
      return secureJson({ success: true, status: safeStatus });
    }

    return secureJson({ error: "Invalid action" }, 400);
  }

  return new Response("Method not allowed", { status: 405 });
};

export const config: Config = {
  path: "/api/withdrawals",
  method: ["GET", "POST"],
};
