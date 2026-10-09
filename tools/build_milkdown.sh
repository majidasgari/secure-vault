#!/usr/bin/env bash
# Build the vendored Milkdown (Crepe) editor used by the Secure Vault web UI.
#
#   tools/build_milkdown.sh
#
# The SPA has no build step and no network at runtime, so the editor is compiled here and the
# resulting single ES module is committed to src/vault/webui/vendor/. Re-run this after bumping the
# version in tools/milkdown-editor/package.json.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/milkdown-editor"
out="$here/../src/vault/webui/vendor"

cd "$src"

if command -v bun >/dev/null 2>&1; then
  runner="bun"
elif command -v npm >/dev/null 2>&1; then
  runner="npm"
else
  echo "build_milkdown.sh: neither bun nor npm is installed" >&2
  exit 1
fi

echo "==> installing the editor's own dependencies ($runner)"
if [ "$runner" = "bun" ]; then
  bun install
else
  npm install
fi

echo "==> building"
if [ "$runner" = "bun" ]; then
  bun run build
else
  npm run build
fi

mkdir -p "$out"
cp "$src/dist/milkdown-editor.js" "$out/milkdown-editor.js"

size=$(wc -c < "$out/milkdown-editor.js")
version=$(sed -n 's/.*"@milkdown\/crepe": "\([^"]*\)".*/\1/p' "$src/package.json" | head -1)
echo "==> wrote src/vault/webui/vendor/milkdown-editor.js ($size bytes, @milkdown/crepe $version)"
