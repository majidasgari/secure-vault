#!/usr/bin/env bash
#
# install-desktop.sh — install the Secure Vault icon + .desktop entry (SPEC/05 §4).
#
# Installs the scalable SVG and rasterised PNGs into the hicolor icon theme (KDE's
# taskbar and menu need raster sizes), writes a freedesktop .desktop entry, refreshes
# the KDE service/icon caches when the tools are available, and prints what it did.
# `--uninstall` reverses all of it. Every step is idempotent.
#
# Usage:
#   tools/install-desktop.sh [--uninstall]
#
# Environment:
#   XDG_DATA_HOME   data dir (default ~/.local/share)
#   PYTHON          interpreter with PySide6 (default <repo>/.venv/bin/python)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-$REPO_ROOT/.venv/bin/python}"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
ICON_BASE="$DATA_HOME/icons/hicolor"
APPS_DIR="$DATA_HOME/applications"
DESKTOP_FILE="$APPS_DIR/secure-vault.desktop"
SVG_SRC="$REPO_ROOT/assets/icon.svg"
APP_ID="secure-vault"
SIZES=(16 22 24 32 48 64 128 256 512)

UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --uninstall) UNINSTALL=1 ;;
    -h | --help)
      echo "Usage: tools/install-desktop.sh [--uninstall]"
      exit 0
      ;;
    *)
      echo "install-desktop: unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

refresh_caches() {
  if command -v kbuildsycoca6 >/dev/null 2>&1; then
    if kbuildsycoca6 --noincremental >/dev/null 2>&1; then
      echo "install-desktop: ran kbuildsycoca6 --noincremental"
    else
      echo "install-desktop: kbuildsycoca6 failed (ignored)" >&2
    fi
  else
    echo "install-desktop: kbuildsycoca6 not found (skipped)"
  fi
  local kcache="$HOME/.cache/icon-cache.kcache"
  if [ -f "$kcache" ]; then
    if rm -f "$kcache"; then
      echo "install-desktop: cleared $kcache"
    else
      echo "install-desktop: could not clear $kcache (ignored)" >&2
    fi
  else
    echo "install-desktop: no icon cache to clear"
  fi
}

install_icons() {
  mkdir -p "$ICON_BASE/scalable/apps"
  cp -f "$SVG_SRC" "$ICON_BASE/scalable/apps/$APP_ID.svg"
  echo "install-desktop: installed $ICON_BASE/scalable/apps/$APP_ID.svg"

  if [ -x "$PY" ] && "$PY" -c 'import PySide6' >/dev/null 2>&1; then
    QT_QPA_PLATFORM=offscreen "$PY" - "$SVG_SRC" "$ICON_BASE" "$APP_ID" "${SIZES[@]}" <<'PYCODE'
import sys
from pathlib import Path

from PySide6.QtCore import QSize
from PySide6.QtGui import QGuiApplication, QIcon

svg = sys.argv[1]
base = Path(sys.argv[2])
app_id = sys.argv[3]
sizes = [int(value) for value in sys.argv[4:]]

app = QGuiApplication.instance() or QGuiApplication(["secure-vault-icons"])
icon = QIcon(svg)
written = 0
for size in sizes:
    for scale in (1, 2):
        pixel = size * scale
        pixmap = icon.pixmap(QSize(pixel, pixel))
        if pixmap.isNull():
            continue
        suffixes = ("",) if scale == 1 else (f"@{scale}", f"@{scale}x")
        for suffix in suffixes:
            directory = base / f"{size}x{size}{suffix}" / "apps"
            directory.mkdir(parents=True, exist_ok=True)
            if pixmap.save(str(directory / f"{app_id}.png")):
                written += 1
print(f"install-desktop: rasterised {written} PNG icon(s) under {base}")
PYCODE
  else
    echo "install-desktop: warning: PySide6 not available in $PY" >&2
    echo "install-desktop: warning: installed only the scalable SVG icon" >&2
  fi
}

uninstall_icons() {
  local removed=0 size
  if [ -f "$ICON_BASE/scalable/apps/$APP_ID.svg" ]; then
    rm -f "$ICON_BASE/scalable/apps/$APP_ID.svg"
    removed=$((removed + 1))
  fi
  for size in "${SIZES[@]}"; do
    for suffix in "" "@2" "@2x"; do
      local png="$ICON_BASE/${size}x${size}${suffix}/apps/$APP_ID.png"
      if [ -f "$png" ]; then
        rm -f "$png"
        removed=$((removed + 1))
      fi
    done
  done
  echo "install-desktop: removed $removed installed icon file(s)"
}

write_desktop_entry() {
  mkdir -p "$APPS_DIR"
  cat >"$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Secure Vault
Name[fa]=گاوصندوق
Comment=Encrypted personal vault (notes + secrets) with MCP access for agents
Exec=$REPO_ROOT/bin/secure-vault
Icon=$APP_ID
Terminal=false
Categories=Utility;Security;
StartupWMClass=secure-vault
EOF
  chmod 644 "$DESKTOP_FILE"
  echo "install-desktop: wrote $DESKTOP_FILE"
}

if [ "$UNINSTALL" -eq 1 ]; then
  uninstall_icons
  if [ -f "$DESKTOP_FILE" ]; then
    rm -f "$DESKTOP_FILE"
    echo "install-desktop: removed $DESKTOP_FILE"
  else
    echo "install-desktop: no desktop entry to remove"
  fi
  refresh_caches
  echo "install-desktop: Secure Vault desktop integration removed."
  exit 0
fi

if [ ! -f "$SVG_SRC" ]; then
  echo "install-desktop: missing icon source: $SVG_SRC" >&2
  exit 1
fi

install_icons
write_desktop_entry
refresh_caches
echo "install-desktop: Secure Vault desktop integration installed."
