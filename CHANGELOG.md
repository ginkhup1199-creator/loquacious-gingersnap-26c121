# Changelog

All notable changes to NexusTrade are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.1.0] — 2026-05-02

### Added
- **Backup & Restore tab** in `admin.html` — export all platform data (users, balances, trades, settings, audit log) as a JSON snapshot and restore from file. Powered by the existing `api-backup.mts` endpoint (`GET /api/v2/backup` / `POST /api/v2/backup`).
- `npm run typecheck` script in `package.json` so `npm run typecheck` works locally and in CI.

### Changed
- **Single master account only** — removed all sub-admin login paths (login overlay button, sub-admin login card in Master Account tab, `subAdminLoginPanel`, `subAdminLoginOverlay`, and `subAdminLogin` stub). The admin panel now supports exactly one authenticated account (the master). Sub-admin *management* (create/list/revoke) is retained in the Master Account tab for reference.
- `applyPermissions()` simplified — no longer branches on role; always shows all nav items for the master account.
- `finishLogin()` simplified — always stores `sessionRole = 'master'`.
- `setLoginMode()` simplified — no argument; clears login error only.
- `resetLoginUI()` simplified — clears master email/password fields only.
- `package.json` version bumped from `1.0.0` to `1.1.0`.

---

## [Unreleased]

### Added
- `netlify/functions/api-health.mts` — health check endpoint at `/api/v2/health`
- `README.md` — comprehensive architecture overview and setup guide
- `DEPLOYMENT.md` — production release checklist
- `CONTRIBUTING.md` — developer contribution guide
- `CHANGELOG.md` — this file
- `LICENSE` — MIT license

---

## [1.1.0] — 2026-05-02

### Changed
- `package.json` — bumped release version to `1.1.0`
- `netlify.toml` — configured `APP_VERSION=1.1.0` for Netlify builds/functions
- `netlify/functions/api-health.mts` — health response now includes timestamp and release version
- `netlify/functions/api-v2-health.mts` — system health response now includes release version
- `DEPLOYMENT.md` / `ADMIN_DEPLOYMENT.md` / `QUICK_REFERENCE.md` — aligned release and Netlify verification guidance with `1.1.0`

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
[1.1.0]: https://github.com/ginkhup1199-creator/loquacious-gingersnap-26c121/releases/tag/v1.1.0
[1.0.0]: https://github.com/ginkhup1199-creator/loquacious-gingersnap-26c121/releases/tag/v1.0.0
