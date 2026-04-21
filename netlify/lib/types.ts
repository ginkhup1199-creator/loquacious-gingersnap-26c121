export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonArray;
export interface JsonObject {
  [key: string]: JsonValue;
}
export interface JsonArray extends Array<JsonValue> {}

export interface ApiVersionInfo {
  apiVersion: "v2";
  appVersion: string;
  commitRef: string;
  deployId: string;
  timestamp: string;
}

export interface ApiHealthInfo {
  status: "ok";
  apiVersion: "v2";
  timestamp: string;
}

export interface ApiStatusInfo {
  status: "ok";
  apiVersion: "v2";
  environment: string;
  timestamp: string;
}
