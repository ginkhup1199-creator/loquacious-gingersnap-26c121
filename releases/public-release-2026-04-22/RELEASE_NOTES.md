# NexusTrade Public Release Package

Release date: 2026-04-22
Release type: Public release candidate
Scope: Frontend + Netlify Functions stabilization pass

## Included Stability Work

1. Frontend stabilization in index.html
- Removed malformed widget-related blocker and validated HTML structure checks.
- Confirmed staking functions are inside the main script block before closing tags.
- Kept visible user flow focused on Binary Options, AI arbitrage, and staking.
- Added tab wiring guard integration to prevent broken visible panel routing.

2. Staking backend hardening in netlify/functions/api-staking.mts
- Uses Request/Context function handler pattern.
- Uses wallet-scoped blob persistence (no shared in-memory stake array).
- Supports frontend workflow: POST stake, POST unstake, GET positions by wallet.
- Includes safe balance return logic when unstaking.

3. Binary levels alignment in netlify/functions/api-levels.mts
- Supports 5 Binary Options levels with min/max capital bands.
- Supports durations up to 14,400 seconds (4 hours).
- Level 5 threshold aligned to capital above 300,000 (starts at 300,001).

4. CI/quality guardrails included
- TypeScript, JS syntax, HTML checks.
- Endpoint uniqueness and /api/v2 enforcement.
- Workflow allowlist + workflow isolation checks.
- Tab wiring integrity check for index navigation.
- Validation/security regression tests.

## Deployment Target

This package is intended for Netlify deployment using repository deployment flow or CLI deploy based on DEPLOYMENT.md.

## Post-Deploy Smoke Test

Run this after production deploy:

```sh
npm run smoke:postdeploy -- https://your-site.netlify.app
```

The smoke check validates frontend availability and core public API routes for health, version, docs, levels, features, settings, and staking reachability.
