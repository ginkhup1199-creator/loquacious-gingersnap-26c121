import type { JsonObject } from "./types.js";
import type { getStore } from "@netlify/blobs";
import { sanitizeString } from "./security.js";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function parseJsonObject(req: Request): Promise<JsonObject> {
  const parsed: unknown = await req.json();
  if (!isRecord(parsed)) {
    throw new Error("Request body must be a JSON object");
  }
  return parsed as JsonObject;
}

export function normalizeWallet(value: unknown): string {
  return sanitizeString(String(value ?? ""), 100).toLowerCase();
}

export function sanitizeWalletLegacy(value: unknown): string {
  return sanitizeString(String(value ?? ""), 100);
}

export function toNumber(value: unknown, fallback = 0): number {
  const parsed = parseFloat(String(value ?? ""));
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function toInteger(value: unknown, fallback = 0): number {
  const parsed = parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function toArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

export function toStringArray(value: unknown): string[] {
  return toArray<unknown>(value)
    .filter((item): item is string => typeof item === "string")
    .map((item) => item);
}

export type BalanceRecord = {
  usdt: number;
  [key: string]: number;
};

export function normalizeBalanceRecord(value: unknown): BalanceRecord {
  const record = isRecord(value) ? value : {};
  return {
    usdt: Math.max(0, toNumber(record.usdt, 0)),
  };
}

export async function loadUsdtBalance(store: ReturnType<typeof getStore>, wallet: string): Promise<BalanceRecord> {
  const stored = await store.get(`balance-${wallet}`, { type: "json" });
  return normalizeBalanceRecord(stored);
}
