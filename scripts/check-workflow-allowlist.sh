#!/usr/bin/env sh
set -eu

APPROVED="
.github/workflows/integrity-check.yml
.github/workflows/auto-deploy.yml
.github/workflows/workflow-guard.yml
.github/workflows/type-check.yml
.github/workflows/security-audit.yml
"

has_path() {
  printf "%s" "$APPROVED" | grep -qx "$1"
}

FAIL=false

for FILE in .github/workflows/*.yml .github/workflows/*.yaml; do
  if [ ! -e "$FILE" ]; then
    continue
  fi

  if has_path "$FILE"; then
    echo "Approved: $FILE"
    continue
  fi

  echo "::error file=$FILE::UNAUTHORIZED workflow file detected: $FILE"
  FAIL=true
done

if [ "$FAIL" = "true" ]; then
  echo "Validation failed: unauthorized workflow file(s) found."
  exit 1
fi

echo "Allowlist validation passed."