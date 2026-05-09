# NexusTrade Public Release (v1.4.0)

This file documents public release readiness for frontend tabs, backend APIs, and wallet-link login behavior.

## Release Scope

- API version enforcement: only `/api/v2/*` endpoints are supported.
- Non-v2 API requests are denied.
- Frontend tab integrity checks are included in automated release validation.
- Wallet link login is enabled for immediate DApp access using URL params.

## Wallet Link Login

Users can open the app with a wallet in the URL and be logged in immediately:

- `https://nexustrade.website/?wallet=<wallet_address>`
- `https://nexustrade.website/#wallet=<wallet_address>`

Supported behavior:

- Wallet is connected immediately.
- User profile is created/synced automatically through `/api/v2/users`.
- The wallet parameter is removed from the URL after login.
- Manual wallet entry and MetaMask login remain available.

## Release Validation Command

Run from project root:

```bash
npm run release:check -- --base-url=https://nexustrade.website
```

Validation covers:

- Required production secrets presence and strength.
- Frontend script syntax and tab wiring.
- Backend route policy (`/api/v2/*` only).
- Live API availability.
- Live endpoint performance thresholds.

## Notes

- If deployment is blocked by Netlify authorization, live checks can fail even when local code is correct.
- Ensure `NETLIFY_AUTH_TOKEN` and `NETLIFY_SITE_ID` are valid in repository secrets for production deploys.
