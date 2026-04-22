#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CHECKER="$SCRIPT_DIR/check-workflow-isolation.sh"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/.github/workflows"

cat > "$TMP_DIR/.github/workflows/safe.yml" <<'EOF'
name: Safe Workflow
on: [push]
jobs:
  safe:
    runs-on: ubuntu-latest
    steps:
      - run: git push origin HEAD
EOF

if ! (cd "$TMP_DIR" && sh "$CHECKER" >/dev/null); then
  echo "Expected isolation check to pass for safe workflow patterns."
  exit 1
fi

cat > "$TMP_DIR/.github/workflows/unsafe-repository-dispatch.yml" <<'EOF'
name: Unsafe Repository Dispatch
on: [push]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo repository_dispatch
EOF
if (cd "$TMP_DIR" && sh "$CHECKER" >/dev/null 2>&1); then
  echo "Expected isolation check to fail for repository_dispatch usage."
  exit 1
fi

cat > "$TMP_DIR/.github/workflows/unsafe-gh-repo.yml" <<'EOF'
name: Unsafe GH Repo
on: [push]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: gh repo view
EOF
if (cd "$TMP_DIR" && sh "$CHECKER" >/dev/null 2>&1); then
  echo "Expected isolation check to fail for gh repo usage."
  exit 1
fi

cat > "$TMP_DIR/.github/workflows/unsafe-explicit-repository.yml" <<'EOF'
name: Unsafe Explicit Repository
on: [push]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: other-owner/other-repo
EOF
if (cd "$TMP_DIR" && sh "$CHECKER" >/dev/null 2>&1); then
  echo "Expected isolation check to fail for explicit repository target."
  exit 1
fi

cat > "$TMP_DIR/.github/workflows/unsafe-git-push.yml" <<'EOF'
name: Unsafe Git Push
on: [push]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: git push upstream HEAD
EOF
if (cd "$TMP_DIR" && sh "$CHECKER" >/dev/null 2>&1); then
  echo "Expected isolation check to fail for non-origin git push."
  exit 1
fi

echo "Workflow isolation tests passed"
