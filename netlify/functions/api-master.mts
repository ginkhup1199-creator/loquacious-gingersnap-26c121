import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import {
  validateAnyAdminSession,
  hasPermission,
  secureJson,
  sanitizeString,
  persistAuditLog,
  getClientIp,
} from "../lib/security.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface UserRecord {
  userId?: string;
  wallet?: string;
  createdAt?: string;
  [key: string]: unknown;
}

interface BalanceRecord {
  usdt?: number;
  btc?: number;
  eth?: number;
  sol?: number;
  bnb?: number;
  xrp?: number;
  ada?: number;
  avax?: number;
  doge?: number;
  usdc?: number;
  [key: string]: unknown;
}

interface TradeRecord {
  id?: number | string;
  type?: string;
  status?: string;
  capital?: number | string;
  profit?: number | string;
  direction?: string;
  createdAt?: string;
  [key: string]: unknown;
}

interface WithdrawalRecord {
  id?: number | string;
  wallet?: string;
  coin?: string;
  network?: string;
  address?: string;
  amount?: number | string;
  date?: string;
  status?: string;
  [key: string]: unknown;
}

interface KycRecord {
  state?: string;
  name?: string;
  docType?: string;
  wallet?: string;
  submittedAt?: string;
  updatedAt?: string;
  [key: string]: unknown;
}

interface AuditEntry {
  timestamp?: string;
  event?: string;
  [key: string]: unknown;
}

interface TransactionRecord {
  id?: string;
  wallet?: string;
  type?: string;
  coin?: string;
  amount?: number | string;
  status?: string;
  notes?: string;
  createdAt?: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Permission map: action → required permission for subadmin
// ---------------------------------------------------------------------------

const ACTION_PERMISSIONS: Record<string, string> = {
  stats:         "view:stats",
  users:         "view:users",
  balances:      "view:balances",
  trades:        "view:trades",
  withdrawals:   "view:withdrawals",
  kyc:           "view:kyc",
  "audit-logs":  "view:audit-logs",
  transactions:  "view:transactions",
};

const VALID_ACTIONS = new Set(Object.keys(ACTION_PERMISSIONS));

// ---------------------------------------------------------------------------
// Data fetchers
// ---------------------------------------------------------------------------

/** Resolve all unique wallet addresses from the all-users list. */
async function resolveWallets(
  store: ReturnType<typeof getStore>
): Promise<string[]> {
  const allUsers = ((await store.get("all-users", { type: "json" })) ?? []) as UserRecord[];
  const wallets = allUsers
    .filter((u) => u && typeof u.wallet === "string")
    .map((u) => (u.wallet as string).toLowerCase());
  return Array.from(new Set(wallets));
}

/** Fetch system-wide statistics. */
async function fetchStats(store: ReturnType<typeof getStore>) {
  const [allUsers, withdrawals, kycPending] = await Promise.all([
    store.get("all-users", { type: "json" }) as Promise<UserRecord[] | null>,
    store.get("withdrawals", { type: "json" }) as Promise<WithdrawalRecord[] | null>,
    store.get("kyc-pending", { type: "json" }) as Promise<string[] | null>,
  ]);

  const users = (allUsers ?? []).filter(
    (u) => u && typeof u.wallet === "string"
  );
  const uniqueWallets = Array.from(
    new Set(users.map((u) => (u.wallet as string).toLowerCase()))
  );

  let activeTrades = 0;
  let totalTrades = 0;
  let totalWalletBalanceUsdt = 0;
  let totalOpenTradeCapitalUsdt = 0;

  await Promise.all(
    uniqueWallets.map(async (wallet) => {
      const [balance, trades] = await Promise.all([
        store.get(`balance-${wallet}`, { type: "json" }) as Promise<BalanceRecord | null>,
        store.get(`trades-${wallet}`, { type: "json" }) as Promise<TradeRecord[] | null>,
      ]);

      totalWalletBalanceUsdt += Number(balance?.usdt ?? 0);

      const walletTrades = trades ?? [];
      totalTrades += walletTrades.length;
      for (const trade of walletTrades) {
        if (trade?.status === "active") {
          activeTrades += 1;
          totalOpenTradeCapitalUsdt += Number(trade.capital ?? 0) || 0;
        }
      }
    })
  );

  const pendingWithdrawals = (withdrawals ?? []).filter(
    (w) => w.status === "Pending"
  ).length;

  const pendingKyc = (kycPending ?? []).length;

  return {
    registeredUsers: users.length,
    pendingKyc,
    pendingWithdrawals,
    totalTrades,
    activeTrades,
    totalWalletBalanceUsdt: Number(totalWalletBalanceUsdt.toFixed(2)),
    totalOpenTradeCapitalUsdt: Number(totalOpenTradeCapitalUsdt.toFixed(2)),
  };
}

/** Fetch all registered users (wallet + registration date). */
async function fetchUsers(store: ReturnType<typeof getStore>) {
  const allUsers = ((await store.get("all-users", { type: "json" })) ?? []) as UserRecord[];
  return allUsers
    .filter((u) => u && typeof u.wallet === "string")
    .map((u) => ({
      userId:    sanitizeString(String(u.userId   ?? ""), 20),
      wallet:    sanitizeString(String(u.wallet   ?? ""), 100),
      createdAt: sanitizeString(String(u.createdAt ?? ""), 30),
    }));
}

/** Fetch all user balances across every coin. */
async function fetchBalances(store: ReturnType<typeof getStore>) {
  const wallets = await resolveWallets(store);
  const results = await Promise.all(
    wallets.map(async (wallet) => {
      const balance = ((await store.get(`balance-${wallet}`, { type: "json" })) ?? {}) as BalanceRecord;
      return {
        wallet,
        usdt:  Number(balance.usdt  ?? 0),
        btc:   Number(balance.btc   ?? 0),
        eth:   Number(balance.eth   ?? 0),
        sol:   Number(balance.sol   ?? 0),
        bnb:   Number(balance.bnb   ?? 0),
        xrp:   Number(balance.xrp   ?? 0),
        ada:   Number(balance.ada   ?? 0),
        avax:  Number(balance.avax  ?? 0),
        doge:  Number(balance.doge  ?? 0),
        usdc:  Number(balance.usdc  ?? 0),
      };
    })
  );
  return results;
}

/** Fetch global trade history across all wallets. */
async function fetchTrades(store: ReturnType<typeof getStore>) {
  const wallets = await resolveWallets(store);
  const perWallet = await Promise.all(
    wallets.map(async (wallet) => {
      const trades = ((await store.get(`trades-${wallet}`, { type: "json" })) ?? []) as TradeRecord[];
      return trades.map((t) => ({
        wallet,
        id:          t.id ?? null,
        type:        sanitizeString(String(t.type      ?? ""), 32),
        status:      sanitizeString(String(t.status    ?? ""), 20),
        capital:     Number(t.capital  ?? 0),
        profit:      Number(t.profit   ?? 0),
        direction:   sanitizeString(String(t.direction ?? ""), 16),
        createdAt:   sanitizeString(String(t.createdAt ?? ""), 30),
      }));
    })
  );
  // Flatten and sort newest-first by createdAt
  return perWallet
    .flat()
    .sort((a, b) => (b.createdAt > a.createdAt ? 1 : -1));
}

/** Fetch all withdrawals (pending and completed). */
async function fetchWithdrawals(store: ReturnType<typeof getStore>) {
  const withdrawals = ((await store.get("withdrawals", { type: "json" })) ?? []) as WithdrawalRecord[];
  return withdrawals.map((w) => ({
    id:      w.id ?? null,
    wallet:  sanitizeString(String(w.wallet  ?? ""), 100),
    coin:    sanitizeString(String(w.coin    ?? ""), 20),
    network: sanitizeString(String(w.network ?? ""), 20),
    address: sanitizeString(String(w.address ?? ""), 200),
    amount:  Number(w.amount ?? 0),
    date:    sanitizeString(String(w.date    ?? ""), 30),
    status:  sanitizeString(String(w.status  ?? ""), 20),
  }));
}

/** Fetch all KYC submissions (pending list + per-wallet records). */
async function fetchKyc(store: ReturnType<typeof getStore>) {
  const wallets = await resolveWallets(store);
  const records = await Promise.all(
    wallets.map(async (wallet) => {
      const kyc = (await store.get(`kyc-${wallet}`, { type: "json" })) as KycRecord | null;
      if (!kyc) return null;
      return {
        wallet,
        state:       sanitizeString(String(kyc.state       ?? "unverified"), 20),
        name:        sanitizeString(String(kyc.name        ?? ""), 100),
        docType:     sanitizeString(String(kyc.docType     ?? ""), 50),
        submittedAt: sanitizeString(String(kyc.submittedAt ?? ""), 30),
        updatedAt:   sanitizeString(String(kyc.updatedAt   ?? ""), 30),
      };
    })
  );
  return records.filter(Boolean);
}

/** Fetch the persisted audit log (newest first, up to 500 entries). */
async function fetchAuditLogs(store: ReturnType<typeof getStore>) {
  const logs = ((await store.get("audit-log", { type: "json" })) ?? []) as AuditEntry[];
  return logs.map((entry) => ({
    timestamp: sanitizeString(String(entry.timestamp ?? ""), 30),
    event:     sanitizeString(String(entry.event     ?? ""), 64),
    ...Object.fromEntries(
      Object.entries(entry)
        .filter(([k]) => k !== "timestamp" && k !== "event")
        .map(([k, v]) => [k, typeof v === "string" ? sanitizeString(v, 200) : v])
    ),
  }));
}

/** Fetch all transactions across all wallets. */
async function fetchTransactions(store: ReturnType<typeof getStore>) {
  const wallets = await resolveWallets(store);
  const perWallet = await Promise.all(
    wallets.map(async (wallet) => {
      const txs = ((await store.get(`transactions-${wallet}`, { type: "json" })) ?? []) as TransactionRecord[];
      return txs.map((tx) => ({
        id:        sanitizeString(String(tx.id        ?? ""), 40),
        wallet,
        type:      sanitizeString(String(tx.type      ?? ""), 20),
        coin:      sanitizeString(String(tx.coin      ?? ""), 10),
        amount:    Number(tx.amount ?? 0),
        status:    sanitizeString(String(tx.status    ?? ""), 20),
        notes:     sanitizeString(String(tx.notes     ?? ""), 200),
        createdAt: sanitizeString(String(tx.createdAt ?? ""), 30),
      }));
    })
  );
  return perWallet
    .flat()
    .sort((a, b) => (b.createdAt > a.createdAt ? 1 : -1));
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * GET /api/v2/master?action=<action>
 *
 * Unified real-time data API for the admin dashboard.
 * Supports both master admins (full access) and subadmins (permission-gated).
 *
 * Actions: stats | users | balances | trades | withdrawals | kyc | audit-logs | transactions
 */
export default async (req: Request, context: Context) => {
  const store = getStore({ name: "app-data", consistency: "strong" });
  const ip    = getClientIp(context);

  // ── Server configuration guard ───────────────────────────────────────────
  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Admin token not configured" }, 503);
  }

  // ── Method guard ─────────────────────────────────────────────────────────
  if (req.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  // ── Parse action ─────────────────────────────────────────────────────────
  const url    = new URL(req.url);
  const action = sanitizeString(url.searchParams.get("action") ?? "", 32).toLowerCase();

  if (!action) {
    return secureJson(
      { error: "Missing required query parameter: action", validActions: Array.from(VALID_ACTIONS) },
      400
    );
  }

  if (!VALID_ACTIONS.has(action)) {
    return secureJson(
      { error: `Invalid action '${action}'`, validActions: Array.from(VALID_ACTIONS) },
      400
    );
  }

  // ── Authentication ────────────────────────────────────────────────────────
  const sessionResult = await validateAnyAdminSession(req, store);
  if (!sessionResult.valid) {
    await persistAuditLog(
      "AUTH_FAILURE",
      { operation: "master-dashboard", action, reason: sessionResult.reason, ip },
      store
    );
    return secureJson({ error: "Unauthorized" }, 401);
  }

  const role = sessionResult.role!; // "master" | "subadmin"

  // ── Permission check for subadmins ────────────────────────────────────────
  const requiredPermission = ACTION_PERMISSIONS[action];
  if (!hasPermission(sessionResult, requiredPermission)) {
    await persistAuditLog(
      "PERMISSION_DENIED",
      {
        operation:  "master-dashboard",
        action,
        role,
        username:   sessionResult.username ?? "(master)",
        permission: requiredPermission,
        ip,
      },
      store
    );
    return secureJson(
      {
        error:              "Forbidden — insufficient permissions",
        requiredPermission,
      },
      403
    );
  }

  // ── Fetch data ────────────────────────────────────────────────────────────
  let data: unknown;
  try {
    switch (action) {
      case "stats":
        data = await fetchStats(store);
        break;
      case "users":
        data = await fetchUsers(store);
        break;
      case "balances":
        data = await fetchBalances(store);
        break;
      case "trades":
        data = await fetchTrades(store);
        break;
      case "withdrawals":
        data = await fetchWithdrawals(store);
        break;
      case "kyc":
        data = await fetchKyc(store);
        break;
      case "audit-logs":
        data = await fetchAuditLogs(store);
        break;
      case "transactions":
        data = await fetchTransactions(store);
        break;
      default:
        return secureJson({ error: "Invalid action" }, 400);
    }
  } catch (err) {
    await persistAuditLog(
      "MASTER_FETCH_ERROR",
      { operation: "master-dashboard", action, error: String(err), ip },
      store
    );
    return secureJson({ error: "Failed to retrieve data" }, 500);
  }

  // ── Audit access ─────────────────────────────────────────────────────────
  await persistAuditLog(
    "MASTER_READ",
    {
      operation: "master-dashboard",
      action,
      role,
      username: sessionResult.username ?? "(master)",
      ip,
    },
    store
  );

  // ── Build response ────────────────────────────────────────────────────────
  const isArray = Array.isArray(data);
  const count   = isArray ? (data as unknown[]).length : undefined;

  return secureJson({
    action,
    role,
    data,
    timestamp: new Date().toISOString(),
    ...(count !== undefined ? { count } : {}),
  });
};

export const config: Config = {
  path:   "/api/v2/master",
  method: ["GET"],
};
