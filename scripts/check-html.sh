#!/bin/sh
set -eu

for file in index.html admin.html; do
  if [ ! -f "$file" ]; then
    echo "Missing HTML file: $file"
    exit 1
  fi

  if ! grep -qi '</html>' "$file"; then
    echo "Missing </html> tag in $file"
    exit 1
  fi

  if ! grep -qi '</body>' "$file"; then
    echo "Missing </body> tag in $file"
    exit 1
  fi

  closing_line=$(grep -ni '</html>' "$file" | tail -n 1 | cut -d: -f1)
  total_lines=$(wc -l < "$file")

  if [ -n "$closing_line" ] && [ "$closing_line" -lt "$total_lines" ]; then
    trailing=$(tail -n +$((closing_line + 1)) "$file" | sed '/^[[:space:]]*$/d')
    if [ -n "$trailing" ]; then
      echo "Unexpected non-empty content after </html> in $file"
      exit 1
    fi
  fi
done

echo "HTML structure checks passed"