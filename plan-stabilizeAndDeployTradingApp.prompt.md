# Plan: Secure CI Guard Workflow Replacement

Replace the previous workflow content with a security-focused CI guard workflow that enforces a strict allowlist for `.github/workflows` and keeps permissions minimal by default.

## Objective
1. Detect unauthorized workflow files during CI.
2. Fail fast with clear logs when policy violations are found.
3. Optionally support controlled remediation on push events.

## Implementation Steps
1. Define a canonical allowlist of approved workflow files.
2. Add a validation job that runs on `pull_request` and `push` for `.github/workflows/**` changes.
3. Scan `.github/workflows/*.yml` and compare each file against the allowlist.
4. Emit `::error` annotations for every unauthorized file.
5. Fail the job if any unauthorized file is detected.
6. If remediation mode is enabled, remove unauthorized files only on trusted push contexts and commit with bot identity.

## Workflow Design Notes
- Keep default permissions as `contents: read`.
- Elevate to `contents: write` only in the remediation job.
- Reuse the existing repository patterns from:
	- `.github/workflows/workflow-guard.yml`
	- `.github/workflows/integrity-check.yml`
	- `.github/workflows/pr-guard.yml`

## Explicit Scope
Included:
- Workflow-file allowlist enforcement.
- CI failure signaling and audit-friendly logs.

Excluded:
- Application feature changes.
- Frontend/backend functional refactors.
- Deployment pipeline redesign outside workflow security.

## Verification
1. Add a temporary test workflow file in `.github/workflows` on a test branch.
2. Confirm the validation job reports unauthorized file(s) and fails.
3. Remove the test file and confirm CI passes.
4. Confirm approved workflows still run normally.

## Rollout Strategy
1. Start in detect-and-fail mode on PRs.
2. Enable remediation only after validation behavior is stable.
3. Keep allowlist synchronized across all workflow guard checks.
