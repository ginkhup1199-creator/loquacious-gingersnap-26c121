# Security Policy

## Supported API Versions

Only API v2 endpoints (`/api/v2/*`) are considered supported for new integrations.

## Reporting a Vulnerability

1. Do not open public issues for security defects.
2. Email the repository owner directly with:
   - affected endpoint or file
   - reproduction steps
   - impact and suggested fix (if available)
3. Rotate affected secrets immediately after remediation.

## Secret Management

- Store production secrets only in GitHub Actions Secrets and Netlify environment variables.
- Never commit `.env` files with real credentials.
- Rotate `ADMIN_TOKEN`, Netlify tokens, and mail credentials on a fixed schedule.
