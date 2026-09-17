#!/usr/bin/env bash
#
# uninstall-desktop.sh — remove the Secure Vault icon + .desktop entry.
#
# Thin wrapper around `tools/install-desktop.sh --uninstall`; see that script for
# the details of what is installed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$REPO_ROOT/tools/install-desktop.sh" --uninstall "$@"
