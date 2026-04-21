# Safe Deployment Guide (Solo Developer)

1. Work on feature branches only.
2. Open a PR and wait for:
   - Type Check workflow
   - Security Audit workflow
   - Code Integrity Check workflow
3. Merge only when all checks pass.
4. Deploys happen from `main` via `auto-deploy.yml`.
5. Validate post-deploy health:
   - `/api/v2/system/health`
   - `/api/v2/system/version`

## Rollback

- Revert the faulty commit and merge.
- Netlify production redeploy triggers automatically.
