import type { getStore } from "@netlify/blobs";

interface SubAdminAccount {
  username: string;
  passwordHash: string;
  permissions: string[];
  createdAt: string;
}

const ACCOUNTS_KEY = "subadmin-accounts";

const DEFAULT_ACCOUNTS: Omit<SubAdminAccount, "createdAt">[] = [
  {
    username: "admin1",
    passwordHash:
      "ad4941386c090ac54142d38b390d313075deff4d873a1c82e3a25540cf611127",
    permissions: [
      "chat",
      "binary-levels",
      "trades",
      "ai-arbitrage",
      "staking",
      "bonus",
    ],
  },
];

export async function seedDefaultAccounts(
  store: ReturnType<typeof getStore>,
): Promise<void> {
  const accounts = ((await store.get(ACCOUNTS_KEY, { type: "json" })) ??
    []) as SubAdminAccount[];
  let updated = false;

  for (const def of DEFAULT_ACCOUNTS) {
    if (!accounts.some((a) => a.username === def.username)) {
      accounts.push({ ...def, createdAt: new Date().toISOString() });
      updated = true;
    }
  }

  if (updated) {
    await store.setJSON(ACCOUNTS_KEY, accounts);
  }
}
