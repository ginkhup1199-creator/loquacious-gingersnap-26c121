# API v2 Reference

Base path: `/api/v2`

## System
- `GET /api/v2/system/health`

## Core endpoints
- `GET|POST /api/v2/users`
- `GET|POST /api/v2/balances`
- `GET|POST /api/v2/trades`
- `GET|POST /api/v2/staking`
- `GET|POST /api/v2/transactions`
- `GET|POST /api/v2/withdrawals`
- `GET|POST /api/v2/wallet`
- `GET|POST /api/v2/features`
- `GET|POST /api/v2/settings`
- `GET|POST /api/v2/kyc`
- `GET /api/v2/levels`
- `GET /api/v2/health`
- `GET /api/v2/market-data`
- `GET|POST /api/v2/chat`

## Admin endpoints
- `GET /api/v2/admin`
- `POST|DELETE /api/v2/admin-accounts`
- `POST /api/v2/admin/session`
- `GET /api/v2/audit-logs`
- `POST /api/v2/trade-control`
- `GET|POST /api/v2/backup`
- `GET|POST /api/v2/addresses`

## Auth

Admin write operations require session token headers as implemented in `api-admin-session` and shared security utilities.
