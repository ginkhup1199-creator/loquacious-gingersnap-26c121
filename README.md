# NexusTrade — Mobile Crypto Wallet DApp

A fully-featured mobile wallet and trading platform built on Netlify, using Netlify Functions for the backend API and Netlify Blobs for persistence.

---

## Live Demo

| URL | Description |
|-----|-------------|
| https://loquacious-gingersnap-26c121.netlify.app/ | User-facing DApp |
| https://loquacious-gingersnap-26c121.netlify.app/admin.html | Admin dashboard |

---

## Architecture Overview

```
NexusTrade
├── index.html              # User DApp (wallet, trading, swaps, binary options, AI bots, KYC)
├── admin.html              # Admin dashboard (user management, KYC, balances, settings)
├── netlify/
│   ├── functions/          # Serverless API endpoints (TypeScript ESM, bundled with esbuild)
│   │   ├── api-admin.mts           # Admin stats & management
│   │   ├── api-admin-session.mts   # 2-step email OTP authentication
│   │   ├── api-addresses.mts       # Deposit address management
│   │   ├── api-balances.mts        # User balance read/write
│   │   ├── api-chat.mts            # Live chat (LLM injection protected)
│   │   ├── api-features.mts        # Feature flag management
│   │   ├── api-health.mts          # Health check endpoint
│   │   ├── api-kyc.mts             # KYC submission & approval
│   │   ├── api-levels.mts          # Binary options & AI arbitrage levels
│   │   ├── api-market-data.mts     # Simulated crypto price feeds
│   │   ├── api-settings.mts        # Global fees & rates
│   │   ├── api-trades.mts          # Trade execution (spot, binary, swap, AI bot)
│   │   ├── api-transactions.mts    # Transaction history
│   │   ├── api-users.mts           # User registration
│   │   ├── api-wallet.mts          # Wallet management
│   │   └── api-withdrawals.mts     # Withdrawal request processing
│   └── lib/
│       └── security.ts     # Shared security utilities (session auth, sanitization, audit log)
├── src/                    # Reference security implementations
├── netlify.toml            # Netlify build & functions configuration
├── package.json
├── .env.example            # Environment variable template (safe to commit)
├── .env.production.example # Production environment template (safe to commit)
└── .gitignore              # Blocks .env and secrets from Git
```

**Storage**: All persistent data is stored in [Netlify Blobs](https://docs.netlify.com/blobs/overview/), a serverless key-value store provided by Netlify.

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v2/health` | None | Health check |
| POST | `/api/v2/users` | None | Register user |
| GET/POST | `/api/v2/balances` | GET: None / POST: Admin | User balances |
| GET/POST | `/api/v2/addresses` | GET: None / POST: Admin | Deposit addresses |
| GET/POST | `/api/v2/trades` | None | Trade history & execution |
| GET/POST | `/api/v2/transactions` | GET: None / POST: Admin | Transaction history |
| GET/POST | `/api/v2/withdrawals` | GET: None / POST: None | Withdrawal management |
| GET/POST | `/api/v2/kyc` | GET: None / POST: Admin (approve/reject only) | KYC submissions |
| GET/POST | `/api/v2/levels` | GET: None / POST: Admin | Binary/AI level config |
| GET/POST | `/api/v2/settings` | GET: None / POST: Admin | Global settings |
| GET/POST | `/api/v2/features` | GET: None / POST: Admin | Feature flags |
| GET | `/api/v2/market-data` | None | Simulated crypto prices |
| POST | `/api/v2/chat` | None | Chat (LLM-protected) |
| GET | `/api/v2/admin` | Admin | Admin statistics |
| POST | `/api/v2/admin/session` | None | OTP login |
| GET/POST | `/api/v2/wallet` | GET: None / POST: Admin | Wallet info |

---

## Quick Start (Local Development)

### Prerequisites

- [Node.js](https://nodejs.org/) v18+
- [Netlify CLI](https://docs.netlify.com/cli/get-started/) — `npm install -g netlify-cli`

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/ginkhup1199-creator/loquacious-gingersnap-26c121.git
cd loquacious-gingersnap-26c121

# 2. Install dependencies
npm install

# 3. Copy environment template
cp .env.example .env

# 4. Fill in your values in .env (see Environment Variables section below)
#    Required: ADMIN_TOKEN, ADMIN_EMAIL, GMAIL_USER, GMAIL_APP_PASSWORD

# 5. Start the local development server
netlify dev
```

The app will be available at `http://localhost:8888`.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ADMIN_TOKEN` | ✅ | Secret token for admin API access (min 32 chars). Generate: `openssl rand -hex 32` |
| `ADMIN_EMAIL` | ✅ | Email address that receives admin OTP codes |
| `GMAIL_USER` | ✅ | Gmail address used to send OTP emails |
| `GMAIL_APP_PASSWORD` | ✅ | Gmail App Password (16 chars). See setup below. |
| `NODE_ENV` | No | `development` or `production` (default: `development`) |

### Gmail App Password Setup

1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable **2-Step Verification** if not already enabled
3. Go to **App Passwords** → Select app: **Mail**, device: your device
4. Click **Generate** and copy the 16-character password
5. Set as `GMAIL_APP_PASSWORD` in your Netlify environment variables

### Generating a Secure Admin Token

```bash
openssl rand -hex 32
```

---

## Admin Login Flow

The admin panel uses 2-step email OTP authentication:

1. Navigate to `/admin.html`
2. **Step 1**: Enter the admin email address (`ADMIN_EMAIL`)
3. A 6-digit OTP code is sent to that email (valid for 10 minutes)
4. **Step 2**: Enter the OTP code
5. A 1-hour session is created upon successful verification

**Session management**: Sessions are stored in Netlify Blobs with a 1-hour TTL. All admin write operations require a valid `X-Session-Token` header.

---

## Security Features

- **2-step email OTP** — No static passwords; codes expire after 10 minutes
- **Session tokens** — 1-hour TTL, stored server-side in Netlify Blobs
- **LLM injection prevention** — 28 regex patterns block prompt-injection attacks on the chat endpoint
- **Input sanitization** — All user inputs are sanitized (null bytes, XSS, URL schemes)
- **Audit logging** — All admin actions are logged with timestamps and client IPs
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, etc.
- **Timing-safe comparison** — Constant-time token comparison prevents timing attacks
- **Constant-time OTP response** — Both valid and invalid emails return 200 to prevent enumeration

See [SECURITY.md](SECURITY.md) and [ENTERPRISE_SECURITY.md](ENTERPRISE_SECURITY.md) for full details.

---

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for the complete production deployment checklist.

**Quick deploy to Netlify:**

1. Fork this repository
2. Go to [Netlify](https://app.netlify.com) → **Add new site** → **Import from Git**
3. Select your forked repository
4. Set environment variables in **Site Settings → Environment Variables**
5. Deploy

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to NexusTrade.

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
