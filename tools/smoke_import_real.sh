#!/usr/bin/env bash
#
# smoke_import_real.sh — run the real Joplin-mirror import (SPEC/04 §7, SPEC/06 §3).
#
# Reads the real Joplin markdown mirror READ-ONLY and imports it into a SCRATCH vault.
# It never touches the user's real vault home: the vault home must be passed explicitly.
#
# The mirror defaults to /data/Cloud/Documents/Notes/joplin-mirror and can be overridden
# with the JOPLIN_MIRROR environment variable. The vault home must be given with --home
# (or SECURE_VAULT_HOME); the script refuses to run without it. The unlock file must be a
# 0600 file holding the master password.
#
# Usage:
#   tools/smoke_import_real.sh --home <scratch vault> --unlock-file <0600 pw file> [args...]
#
# Examples (run from the repository root):
#   # dry run first
#   tools/smoke_import_real.sh --home /tmp/sv-real --unlock-file /tmp/sv-real.pw --dry-run
#   # then the real import, writing the report
#   tools/smoke_import_real.sh --home /tmp/sv-real --unlock-file /tmp/sv-real.pw \
#       --report docs/reports/joplin-real.md
#
# Any extra arguments are forwarded verbatim to tools/import_joplin.py.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$REPO_ROOT/.venv/bin/python}"
MIRROR="${JOPLIN_MIRROR:-/data/Cloud/Documents/Notes/joplin-mirror}"

HOME_DIR="${SECURE_VAULT_HOME:-}"
UNLOCK_FILE="${SECURE_VAULT_UNLOCK_FILE:-}"
PASSTHROUGH=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --home)
      HOME_DIR="$2"
      shift 2
      ;;
    --home=*)
      HOME_DIR="${1#*=}"
      shift
      ;;
    --unlock-file)
      UNLOCK_FILE="$2"
      shift 2
      ;;
    --unlock-file=*)
      UNLOCK_FILE="${1#*=}"
      shift
      ;;
    *)
      PASSTHROUGH+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$HOME_DIR" ]]; then
  echo "error: refusing to run without an explicit vault home (--home or SECURE_VAULT_HOME)" >&2
  exit 2
fi
if [[ -z "$UNLOCK_FILE" ]]; then
  echo "error: --unlock-file <0600 password file> is required" >&2
  exit 2
fi
if [[ ! -r "$MIRROR/_meta/index.json" ]]; then
  echo "error: Joplin mirror not found or unreadable: $MIRROR" >&2
  exit 2
fi
case "$HOME_DIR" in
  "$MIRROR" | "$MIRROR"/*)
    echo "error: the vault home must not be inside the mirror: $HOME_DIR" >&2
    exit 2
    ;;
esac

echo "mirror: $MIRROR"
echo "vault:  $HOME_DIR"
exec "$PYTHON" "$REPO_ROOT/tools/import_joplin.py" \
  --home "$HOME_DIR" \
  --unlock-file "$UNLOCK_FILE" \
  --mirror "$MIRROR" \
  ${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}
