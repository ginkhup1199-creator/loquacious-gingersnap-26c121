# Changelog

All notable changes to NexusTrade are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

---

## [1.1.0] — 2026-05-01

### Added

**New API Endpoints**
- `api-v2-health.mts` — versioned health check at `/api/v2/system/health` with ISO timestamp
- `api-admin-accounts.mts` — sub-admin account management (create/revoke via master-only `/api/v2/admin-accounts`)
- `api-backup.mts` — data backup and restore endpoint (`/api/v2/backup`) for disaster recovery
- `api-k-lineup.mts` — K-Lineup trading signal management (`/api/v2/k-lineup`)
- `api-staking.mts` — staking plan management (`/api/v2/staking`)
- `api-trade-control.mts` — global and per-user trade stop/resume controls (`/api/v2/trade-control`)

**Security Enhancements**
- In-process per-IP sliding-window rate limiting (`checkRateLimit`) applied to all write endpoints
- `persistAuditLog()` — durable audit trail in Netlify Blobs with 500-entry rolling window, surfaced via `/api/v2/audit-logs`
- Sub-admin session model: `validateAnyAdminSession()` returns role + permissions for `hasPermission()` checks
- SIWE (Sign-In with Ethereum) authentication: nonce/verify/session endpoints via `api-siwe.mts`

**Frontend**
- Admin dashboard: Staking, Deposit Addresses, K-Lineup, Audit Logs, and Master Account tabs wired to their respective API endpoints
- User app: AI Arbitrage tab (cycleTime/profitPercent), Earn & Stake tab connected to staking API
- Live BTC/ETH prices via Binance WebSocket with auto-reconnect and Coinbase/CoinGecko fallback

**Configuration & Tooling**
- `netlify.toml` CSP updated: `wss://stream.binance.com:9443`, `https://api.coingecko.com`, `https://api.coinbase.com`, `https://cdn.jsdelivr.net` added to appropriate directives
- `auto-deploy.yml` — CI/CD deploy workflow now passes `--site` and `--auth` flags explicitly; auth-token guard step prevents silent failures on missing secrets
- `DEPLOYMENT.md` — added troubleshooting section for `"Project not found. Please rerun netlify link"` deploy error
- `ADMIN_DEPLOYMENT.md` — aligned with v1.1.0 endpoint paths and sub-admin model

### Changed
- `package.json` version bumped `1.0.0` → `1.1.0`
- All Netlify functions import shared utilities from `../lib/security.js` (NodeNext ESM, source `.mts`)
- Health endpoint expected response updated in docs: `{ status, apiVersion, timestamp }`

### Fixed
- Auto-deploy workflow now validates `NETLIFY_AUTH_TOKEN` is set before attempting deploy, surfacing a clear error instead of the cryptic `"Project not found. Please rerun netlify link"` message
- Rate limiting section in `DEPLOYMENT.md` updated to reflect actual in-process implementation

---

## [1.0.0] — 2026-04-05

### Added — Public Release

**Core API Endpoints**
- `api-users.mts` — user registration
- `api-balances.mts` — USDT balance management (admin write)
- `api-addresses.mts` — deposit address management
- `api-trades.mts` — trade execution (spot, binary options, swap, AI bot deployments)
- `api-transactions.mts` — full transaction history with admin-only write
- `api-withdrawals.mts` — withdrawal request processing
- `api-kyc.mts` — KYC submission and admin approval
- `api-levels.mts` — binary options and AI arbitrage level configuration
- `api-settings.mts` — global fees and rates
- `api-features.mts` — feature flag management
- `api-market-data.mts` — simulated crypto price feeds for market data display
- `api-chat.mts` — live chat with LLM injection protection
- `api-admin.mts` — admin statistics dashboard
- `api-wallet.mts` — wallet management

**Authentication (PR #5)**
- 2-step email OTP admin login via `api-admin-session.mts`
- 6-digit OTP codes sent via Gmail SMTP (nodemailer)
- OTP stored as SHA-256 hash in Netlify Blobs with 10-minute TTL
- 5 maximum OTP attempts before invalidation
- Constant-time responses to prevent email enumeration

**Security (PR #4)**
- `netlify/lib/security.ts` — shared security utilities for all API functions
- Session-based authentication with 1-hour TTL
- 28-pattern LLM prompt-injection detection
- HTML/XSS input sanitization with multi-pass tag removal
- Audit logging for all admin events
- Standard security headers on all responses (no-store, X-Frame-Options, etc.)
- Timing-safe session token comparison

**Frontend**
- `index.html` — full mobile DApp (wallet, trading, swaps, binary options, AI bots, staking, KYC)
- `admin.html` — admin dashboard with 2-step email OTP login
- Live BTC/ETH prices via Binance WebSocket with simulation fallback
- MetaMask wallet integration with demo wallet fallback

**Configuration**
- `netlify.toml` — Netlify build and functions configuration (esbuild bundler)
- `.env.example` — complete environment variable template
- `.env.production.example` — production environment guidance
- `.gitignore` — blocks secrets, node_modules, build artifacts
- `package.json` — dependencies: `@netlify/blobs`, `@netlify/functions`, `nodemailer`

**Documentation**
- `SECURITY.md` — security configuration and endpoint protection reference
- `ENTERPRISE_SECURITY.md` — enterprise security implementation details

---

[Unreleased]: https://github.com/ginkhup1199-creator/loquacious-gingersnap-26c121/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/ginkhup1199-creator/loquacious-gingersnap-26c121/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ginkhup1199-creator/loquacious-gingersnap-26c121/releases/tag/v1.0.0
