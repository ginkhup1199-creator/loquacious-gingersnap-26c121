# TypeScript Types

Shared API contracts and validators:

- `netlify/lib/types.ts`
  - `JsonObject`, `JsonValue`
  - `ApiVersionInfo`
  - `ApiHealthInfo`
  - `ApiStatusInfo`
- `netlify/lib/validation.ts`
  - `isRecord(value)`
  - `parseJsonObject(req)`

Use `parseJsonObject` for request body parsing before accessing fields.
