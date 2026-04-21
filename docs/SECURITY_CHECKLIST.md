# Security Checklist

- [ ] Enable branch protection on `main`
- [ ] Require PR + status checks before merge
- [ ] Keep CODEOWNERS enabled for sensitive paths
- [ ] Store secrets only in GitHub/Netlify secret stores
- [ ] Rotate `ADMIN_TOKEN`, Netlify token, and email credentials
- [ ] Review `npm audit` results regularly
- [ ] Verify production health after every deploy
