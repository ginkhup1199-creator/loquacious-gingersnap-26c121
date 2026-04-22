#!/bin/sh
set -eu

files=$(find src netlify -type f -name '*.js' 2>/dev/null || true)

if [ -z "$files" ]; then
  echo "No source JS files found"
  exit 0
fi

printf '%s\n' "$files" | while IFS= read -r file; do
  [ -n "$file" ] || continue
  node --check "$file"
done

echo "JS syntax checks passed"