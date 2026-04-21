# API Migration: v1 to v2

## Path change

Replace:
- `/api/<endpoint>`

With:
- `/api/v2/<endpoint>`

## Recommended rollout

1. Update client base URL to `/api/v2`.
2. Validate critical endpoints first (`health`, `market-data`, `features`).
3. Remove v1 callers once all clients are migrated.

## Compatibility

`netlify.toml` includes a redirect from `/api/*` to `/api/v2/:splat` for transition support.
