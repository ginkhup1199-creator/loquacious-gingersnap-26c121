#!/usr/bin/env sh
set -eu

REMEDIATE=false
if [ "${1:-}" = "--remediate" ]; then
  REMEDIATE=true
fi

APPROVED="
.github/workflows/pr-guard.yml
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
REMOVED=""

for FILE in .github/workflows/*.yml .github/workflows/*.yaml; do
  if [ ! -e "$FILE" ]; then
    continue
  fi

  if has_path "$FILE"; then
    echo "Approved: $FILE"
    continue
  fi

  if [ "$REMEDIATE" = "true" ]; then
    echo "Deleting unauthorized workflow file: $FILE"
    git rm --force "$FILE"
    REMOVED="$REMOVED $FILE"
  else
    echo "::error file=$FILE::UNAUTHORIZED workflow file detected: $FILE"
    FAIL=true
  fi
done

if [ "$REMEDIATE" = "true" ]; then
  if [ -n "$REMOVED" ]; then
    echo "Removed unauthorized workflow file(s):$REMOVED"
  else
    echo "All workflow files are approved. No action needed."
  fi
  exit 0
fi

if [ "$FAIL" = "true" ]; then
  echo "Validation failed: unauthorized workflow file(s) found."
  exit 1
fi

echo "Allowlist validation passed."