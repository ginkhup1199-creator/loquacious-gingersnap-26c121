#!/usr/bin/env sh
set -eu

BASE_URL="${1:-${BASE_URL:-}}"

if [ -z "$BASE_URL" ]; then
  echo "Usage: sh scripts/post-deploy-smoke.sh https://your-site.netlify.app"
  exit 1
fi

BASE_URL="${BASE_URL%/}"

pass() {
  echo "PASS: $1"
}

fail() {
  echo "FAIL: $1"
  exit 1
}

check_status_200() {
  URL="$1"
  NAME="$2"
  CODE=$(curl -sS -o /dev/null -w "%{http_code}" "$URL") || fail "$NAME request failed"
  [ "$CODE" = "200" ] || fail "$NAME expected HTTP 200, got $CODE"
  pass "$NAME"
}

check_json_contains() {
  URL="$1"
  NAME="$2"
  NEEDLE="$3"
  BODY=$(curl -sS "$URL") || fail "$NAME request failed"
  echo "$BODY" | grep -q "$NEEDLE" || fail "$NAME response missing '$NEEDLE'"
  pass "$NAME contains $NEEDLE"
}

echo "Running post-deploy smoke checks against $BASE_URL"

check_status_200 "$BASE_URL/" "Frontend root"
check_json_contains "$BASE_URL/api/v2/system/health" "System health" '"status":"ok"'
check_json_contains "$BASE_URL/api/v2/health" "V2 health" '"status":"ok"'
check_status_200 "$BASE_URL/api/v2/system/version" "System version"
check_json_contains "$BASE_URL/api/v2/docs" "API docs index" '"endpoints"'
check_json_contains "$BASE_URL/api/v2/levels" "Levels endpoint" '"binaryLevels"'
check_json_contains "$BASE_URL/api/v2/features" "Features endpoint" '"binary"'
check_json_contains "$BASE_URL/api/v2/settings" "Settings endpoint" '"supportEmail"'

# Wallet-scoped staking should be reachable and return a positions array.
check_json_contains "$BASE_URL/api/v2/staking?wallet=release-smoke-wallet" "Staking endpoint" '"positions"'

echo "All post-deploy smoke checks passed."
