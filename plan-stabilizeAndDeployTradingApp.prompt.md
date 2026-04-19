# Plan: Stabilize and Deploy Trading App

Bring the app to a deployment-ready state by fixing the current frontend blockers, replacing the broken staking backend, aligning the Binary Options configuration to the requested business rules, and then deploying to Netlify with a structured verification pass.

## Immediate execution target
Implement only the three blocking fixes first:
- index.html
- netlify/functions/api-staking.mts
- netlify/functions/api-levels.mts

No other cleanup should block this pass unless it is required to make those three work.

## Exact active error fix
1. In index.html, replace the malformed TradingView timeline embed block near the Latest Crypto News section with a valid embed or a simple fallback.
2. Move the entire staking functions block that currently begins after the closing HTML tags back into the main in-page script section before the final closing body tag.
3. After those two edits, rerun editor diagnostics and confirm the semicolon parse errors are gone.

## Three-file implementation handoff
### 1. index.html
- Remove the malformed external news widget block that is causing the current parse errors.
- Move the staking functions into the main script block before the final closing body tag.
- Keep the visible user app centered on Binary Options, AI arbitrage, and staking.
- Recheck tab wiring so all visible panels still point to real section IDs after cleanup.

### 2. netlify/functions/api-staking.mts
- Replace the old handler with the same Request and Context pattern used by the other Netlify functions.
- Use blob-backed wallet-scoped staking positions instead of the shared in-memory array.
- Support the exact frontend workflow already present in the app: POST stake, POST unstake, GET positions by wallet, and safe balance updates after claim.

### 3. netlify/functions/api-levels.mts
- Change the Binary Options defaults and validation to the requested five levels.
- Extend the data structure to support capital bands rather than a single capital number.
- Increase the allowed trade duration ceiling so the 2-hour and 4-hour tiers are valid.

## Trading level requirements confirmed
- Use the Binary Options trading name for now and do not add or keep a separate Spot Trade experience in the main plan.
- The app should focus solely on trading, AI arbitrage, and staking.
- Social-style or nonessential engagement sections should be removed or de-emphasized from the public app.

Binary Options tiers:
- Level 1: 18 percent profit, capital range 300 to 20,000 USDT, trade time 240 seconds
- Level 2: 23 percent profit, capital range 20,001 to 50,000 USDT, trade time 360 seconds
- Level 3: 35 percent profit, capital range 50,001 to 100,000 USDT, trade time 360 seconds
- Level 4: 50 percent profit, capital range 100,001 to 300,000 USDT, trade time 2 hours
- Level 5: 100 percent profit, capital above 300,000 USDT, trade time 4 hours

Implementation note: the current levels model only stores a single capital value and currently caps trade duration at 3600 seconds, so the schema and validation in the levels endpoint must be extended to support min and max capital bands and durations up to 14,400 seconds.

## Recommended execution order and dependency notes
1. Start with index.html because it has the only currently confirmed active editor errors and blocks clean frontend validation.
2. Then repair netlify/functions/api-staking.mts because staking persistence is the main functional backend defect.
3. Then update netlify/functions/api-levels.mts so the Binary Options product rules match the requested business model.
4. Only after those three pass verification should deployment through Netlify proceed.

## Post-deployment sign-off
1. Confirm the public app loads without console or editor-facing structural issues.
2. Verify the core public product scope works end-to-end: Binary Options trading, AI arbitrage, and staking.
3. Confirm data persistence after refresh, logout, and repeated function invocations.
4. Confirm admin control stays private and cannot be accessed from the public flow without a valid session.
5. Watch the health endpoint, audit logs, and first live user actions for regressions immediately after release.
6. If any regression appears in production, pause changes and use the documented rollback route in the deployment guide.
