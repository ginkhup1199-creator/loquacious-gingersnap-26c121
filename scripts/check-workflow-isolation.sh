#!/usr/bin/env sh
set -eu

FAIL=false

for FILE in .github/workflows/*.yml .github/workflows/*.yaml; do
  if [ ! -e "$FILE" ]; then
    continue
  fi

  while IFS= read -r ENTRY; do
    LINE_NO=${ENTRY%%:*}
    LINE_TEXT=${ENTRY#*:}

    if echo "$LINE_TEXT" | grep -Eq 'repository_dispatch'; then
      echo "::error file=$FILE,line=$LINE_NO::repository_dispatch is not allowed (cross-repo/project signaling risk)."
      FAIL=true
    fi

    if echo "$LINE_TEXT" | grep -Eq 'gh[[:space:]]+repo|gh[[:space:]]+api'; then
      echo "::error file=$FILE,line=$LINE_NO::GitHub CLI repository operations are not allowed in workflows."
      FAIL=true
    fi

    if echo "$LINE_TEXT" | grep -Eq '^[[:space:]]*repository:'; then
      echo "::error file=$FILE,line=$LINE_NO::Explicit repository checkout/target is not allowed in workflows."
      FAIL=true
    fi

    if echo "$LINE_TEXT" | grep -Eq 'git[[:space:]]+push'; then
      if ! echo "$LINE_TEXT" | grep -Eq 'git[[:space:]]+push[[:space:]]+origin([[:space:]]|$)'; then
        echo "::error file=$FILE,line=$LINE_NO::Only pushes to origin are allowed in workflows."
        FAIL=true
      fi
    fi
  done <<EOF
$(nl -ba "$FILE" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]\+/:/')
EOF

done

if [ "$FAIL" = "true" ]; then
  echo "Workflow isolation check failed."
  exit 1
fi

echo "Workflow isolation check passed."
