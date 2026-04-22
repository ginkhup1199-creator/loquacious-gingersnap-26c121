#!/usr/bin/env sh
set -eu

FILE="index.html"

if [ ! -f "$FILE" ]; then
  echo "Tab wiring check failed: $FILE not found."
  exit 1
fi

FAIL=false

TARGETS=$(grep -oE '<[^>]*onclick="switchTab\('\''[^'\'']+'\''\)"' "$FILE" | sed -E "s/.*switchTab\('([^']+)'\).*/\1/" | sort -u)

for TARGET in $TARGETS; do
  if ! grep -q "id=\"$TARGET\"" "$FILE"; then
    echo "::error file=$FILE::Tab target '$TARGET' is referenced by onclick but no matching id exists."
    FAIL=true
  fi
done

if [ "$FAIL" = "true" ]; then
  echo "Tab wiring check failed."
  exit 1
fi

echo "Tab wiring check passed."
