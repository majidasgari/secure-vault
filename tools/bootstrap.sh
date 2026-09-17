#!/usr/bin/env bash
#
# bootstrap.sh — idempotent Secure Vault setup (SPEC/05 §2).
#
# Creates .venv, points it at the local PyPI mirror, installs the runtime
# dependencies, downloads the bundled Vazirmatn fonts when they are missing (the
# font is optional: a failed download is a warning, never an error) and optionally
# installs the desktop entry. Safe to run repeatedly.
#
# Usage:
#   tools/bootstrap.sh [--skip-deps] [--desktop]
#
# Environment:
#   PYTHON           interpreter used to create the venv (default /usr/bin/python3)
#   PIP_INDEX_URL    mirror index URL (default the runflare mirror)
#   PIP_TRUSTED_HOST matching trusted host for the mirror
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-/usr/bin/python3}"
VENV="$REPO_ROOT/.venv"
VENV_PY="$VENV/bin/python"
REQUIREMENTS="$REPO_ROOT/requirements.txt"
MIRROR_INDEX="${PIP_INDEX_URL:-https://mirror-pypi.runflare.com/simple/}"
MIRROR_HOST="${PIP_TRUSTED_HOST:-mirror-pypi.runflare.com}"

SKIP_DEPS=0
DO_DESKTOP=0

usage() {
  cat <<EOF
Secure Vault bootstrap

Usage: tools/bootstrap.sh [--skip-deps] [--desktop]

  --skip-deps   do not run pip install (dependencies already present)
  --desktop     install the KDE/GNOME desktop entry and icons afterwards
  -h, --help    show this help

Environment:
  PYTHON=$PY
  PIP_INDEX_URL=$MIRROR_INDEX
  PIP_TRUSTED_HOST=$MIRROR_HOST
EOF
}

for arg in "$@"; do
  case "$arg" in
    --skip-deps) SKIP_DEPS=1 ;;
    --desktop) DO_DESKTOP=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "bootstrap: unknown option: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

# 1. Pick the interpreter and refuse the Hermes venv python / anything < 3.11.
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "bootstrap: python interpreter not found: $PY" >&2
  exit 1
fi
REAL_PY="$(readlink -f "$(command -v "$PY")")"
case "$REAL_PY" in
  *[Hh]ermes*)
    echo "bootstrap: refusing to use the Hermes venv python ($REAL_PY)" >&2
    echo "bootstrap: set PYTHON=/usr/bin/python3 and run again" >&2
    exit 1
    ;;
esac
if ! "$PY" - <<'PYCODE'
import sys

if sys.version_info < (3, 11):
    raise SystemExit(
        "Secure Vault needs Python >= 3.11 (found %d.%d)"
        % (sys.version_info[0], sys.version_info[1])
    )
PYCODE
then
  echo "bootstrap: refusing to continue with $REAL_PY" >&2
  exit 1
fi
echo "bootstrap: using $REAL_PY ($("$PY" -c 'import platform; print(platform.python_version())'))"

# 2. Create the virtualenv when it is missing.
if [ -x "$VENV_PY" ]; then
  echo "bootstrap: virtualenv already present at $VENV"
else
  echo "bootstrap: creating virtualenv at $VENV"
  "$PY" -m venv "$VENV"
fi

# 3. Point the venv at the configured mirror unless it already has a pip.conf.
PIP_CONF="$VENV/pip.conf"
if [ -f "$PIP_CONF" ]; then
  echo "bootstrap: keeping existing $PIP_CONF"
else
  cat >"$PIP_CONF" <<EOF
[global]
index-url = $MIRROR_INDEX
trusted-host = $MIRROR_HOST
EOF
  echo "bootstrap: wrote $PIP_CONF (index-url = $MIRROR_INDEX)"
fi

# 4. Install the runtime dependencies.
if [ "$SKIP_DEPS" -eq 1 ]; then
  echo "bootstrap: --skip-deps, not installing Python packages"
else
  echo "bootstrap: installing runtime dependencies from requirements.txt"
  "$VENV_PY" -m pip install -r "$REQUIREMENTS"
fi

# 5. Download the optional Vazirmatn fonts when they are missing.
fetch_font() {
  local name="$1"
  local url="$2"
  local dest="$REPO_ROOT/assets/$name"
  local tmp
  if [ -s "$dest" ]; then
    echo "bootstrap: font already present: assets/$name"
    return 0
  fi
  tmp="$dest.tmp"
  if command -v curl >/dev/null 2>&1 && curl -fsSL "$url" -o "$tmp" 2>/dev/null; then
    mv "$tmp" "$dest"
    echo "bootstrap: downloaded assets/$name"
  elif command -v wget >/dev/null 2>&1 && wget -qO "$tmp" "$url" 2>/dev/null; then
    mv "$tmp" "$dest"
    echo "bootstrap: downloaded assets/$name"
  else
    rm -f "$tmp"
    echo "bootstrap: warning: could not download assets/$name" >&2
    echo "bootstrap: warning: the font is optional — the app runs without it" >&2
  fi
}

FONT_BASE="https://raw.githubusercontent.com/rastikerdar/vazirmatn/master/fonts/ttf"
fetch_font "Vazirmatn-Regular.ttf" "$FONT_BASE/Vazirmatn-Regular.ttf"
fetch_font "Vazirmatn-Bold.ttf" "$FONT_BASE/Vazirmatn-Bold.ttf"

# 6. Optional desktop integration.
if [ "$DO_DESKTOP" -eq 1 ]; then
  echo "bootstrap: installing the desktop entry"
  bash "$REPO_ROOT/tools/install-desktop.sh"
fi

# 7. Print the two commands the user needs.
cat <<EOF

bootstrap: done.

  run the app:   $REPO_ROOT/bin/secure-vault
  MCP entry:     $REPO_ROOT/bin/secure-vault-mcp

Register the MCP entry point with Hermes (see docs/MCP.md for the full snippet):
  hermes mcp add secure-vault --command "$REPO_ROOT/bin/secure-vault-mcp"
EOF
