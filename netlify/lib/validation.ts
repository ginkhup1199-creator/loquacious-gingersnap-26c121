import type { JsonObject } from "./types.js";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function parseJsonObject(req: Request): Promise<JsonObject> {
  const parsed: unknown = await req.json();
  if (!isRecord(parsed)) {
    throw new Error("Invalid JSON object");
  }
  return parsed as JsonObject;
}
