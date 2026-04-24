#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CHECKER="$SCRIPT_DIR/check-workflow-allowlist.sh"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/.github/workflows"

APPROVED_FILES="
.github/workflows/integrity-check.yml
.github/workflows/auto-deploy.yml
.github/workflows/workflow-guard.yml
.github/workflows/type-check.yml
.github/workflows/security-audit.yml
"

for FILE in $APPROVED_FILES; do
  mkdir -p "$TMP_DIR/$(dirname "$FILE")"
  : > "$TMP_DIR/$FILE"
done

if ! (cd "$TMP_DIR" && sh "$CHECKER" >/dev/null); then
  echo "Expected allowlist validation to pass for approved workflows."
  exit 1
fi

: > "$TMP_DIR/.github/workflows/unauthorized.yml"
if (cd "$TMP_DIR" && sh "$CHECKER" >/dev/null 2>&1); then
  echo "Expected allowlist validation to fail for unauthorized workflows."
  exit 1
fi

: > "$TMP_DIR/.github/workflows/unauthorized.yaml"
if (cd "$TMP_DIR" && sh "$CHECKER" >/dev/null 2>&1); then
  echo "Expected allowlist validation to fail for unauthorized .yaml workflows."
  exit 1
fi

echo "Workflow allowlist tests passed"
