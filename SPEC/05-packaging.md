# SPEC 05 — Packaging, launcher, desktop integration, Windows portable, docs

Files: `requirements*.txt`, `bin/secure-vault`, `tools/bootstrap.sh`, `tools/install-desktop.sh`,
`tools/build_windows_portable.py`, `assets/*`, `README.md`, `docs/*`, `.gitignore`, `LICENSE`.

## 1. `requirements.txt` (runtime, pinned with `>=`, resolved in `.venv`)

```
PySide6>=6.10,<7
cryptography>=44
argon2-cffi>=23
markdown-it-py>=3
Pygments>=2.17
```
`requirements-semantic.txt` (opt-in heavy extra, never installed by bootstrap):
```
sentence-transformers>=3
```
The app must **import cleanly without** `requirements-semantic.txt`.

## 2. `tools/bootstrap.sh`

Bash, `set -euo pipefail`, fully idempotent and **offline-hostile-network aware**:
1. `PY=${PYTHON:-/usr/bin/python3}` — refuse to run with the Hermes venv python; require ≥ 3.11.
2. create `.venv` if missing.
3. write `.venv/pip.conf` with the mirror index (`${PIP_INDEX_URL:-https://mirror-pypi.runflare.com/simple/}`
   + matching `trusted-host`) unless the venv already has one.
4. `pip install -r requirements.txt` (skip with `--skip-deps`).
5. download `assets/Vazirmatn-Regular.ttf` (+ `Vazirmatn-Bold.ttf`) if missing, from
   `https://raw.githubusercontent.com/rastikerdar/vazirmatn/master/fonts/ttf/Vazirmatn-Regular.ttf`
   (verified reachable); on failure print a warning and continue (the font is optional — the app
   must run without it).
6. optionally install the desktop entry when `--desktop` is passed.
7. print the two commands the user needs (run + MCP registration).

## 3. `bin/secure-vault`

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || { echo "…run tools/bootstrap.sh first" >&2; exit 1; }
exec "$PY" -m vault "$@"
```
`PYTHONPATH="$ROOT/src"` is set by `src/vault/__main__.py`'s package layout — the launchers
(`bin/secure-vault`, `tools/*.py` clis, `tests/run_tests.py`) must all work by adding
`$ROOT/src` (use a tiny `tools/_bootstrap_path.py` helper or `sys.path.insert` at the top of
each entry point; document the `PYTHONPATH=src` alternative).

## 4. `tools/install-desktop.sh`

* Installs `assets/icon.svg` into `~/.local/share/icons/hicolor/scalable/apps/secure-vault.svg`
  **and** rasterised PNGs into the size dirs (`16x16 … 512x512` + `@2x`) — the KDE icon cache
  needs raster sizes for the taskbar; render them with PySide6 (`QIcon(...).pixmap(n, n).save(...)`)
  since ImageMagick may be absent. Skip gracefully if PySide6 is unavailable.
* Writes `~/.local/share/applications/secure-vault.desktop`:
  `Name=Secure Vault`, `Name[fa]=گاوصندوق`, `Exec=<repo>/bin/secure-vault`, `Icon=secure-vault`,
  `Terminal=false`, `Categories=Utility;Security;`, `StartupWMClass=secure-vault`,
  `Comment=Encrypted personal vault (notes + secrets) with MCP access for agents`.
* Runs `kbuildsycoca6 --noincremental` and clears `~/.cache/icon-cache.kcache` when present
  (both optional; ignore failures) and prints what it did. `--uninstall` reverses it.

## 5. `tools/build_windows_portable.py`

Targets a **Windows** run from a folder, built on this Linux box:

```
python tools/build_windows_portable.py [--python-version 3.12.10] [--dest portable/win]
                                      [--check] [--force]
```
* `--check` = **offline validation only** (the mode that must pass here): validates the repo
  layout, that every runtime import is covered by `requirements.txt`, that `bin/secure-vault`
  and the entry modules exist, and that the destination is writable. Prints `CHECK OK`.
* Real run (documented, expected to be run later / on a machine with the mirror reachable):
  1. download the *embeddable* CPython zip
     (`https://www.python.org/ftp/python/<ver>/python-<ver>-embed-amd64.zip` — python.org is
     reachable from here), unpack into `--dest`;
  2. enable `import site` in `python*._pth` (append `Lib/site-packages` + `../src`);
  3. get `pip` (`get-pip.py` or the zipapp) and `pip install --target <dest>/Lib/site-packages
     --only-binary=:all: --platform win_amd64 --python-version <ver> --implementation cp
     --index-url <mirror> -r requirements.txt` — refuse if any package has no wheel (it must not
     compile);
  4. copy `src/`, `i18n/`, `assets/`, `bin/` (as `run.bat` + `secure-vault.cmd`) into the folder;
  5. write `portable/win/README.txt` (Persian+English) with the run instructions and the fact
     that the vault home must be chosen on first run;
  6. `--force` wipes the destination first.
* The script must never be run automatically by bootstrap, and `portable/` is git-ignored.

## 6. `.gitignore`

```
.venv/  portable/  __pycache__/  *.pyc  .pytest_cache/
docs/reports/    # importer reports (keep the directory with a .gitkeep instead)
*.tmp
```
Keep `docs/reports/.gitkeep` so the directory exists.

## 7. `docs/` (all in English, Persian quotes where the design is cited)

| file | content |
|---|---|
| `DESIGN.md` | the original Persian design, copied verbatim from `/data/Cloud/Documents/Notes/joplin-mirror/کاری/ایده‌ها/secure-vault/DESIGN.md` (byte-identical; it is the user's document — never edit it) |
| `ARCHITECTURE.md` | process model (GUI = daemon, MCP bridge, headless daemon), data layout with an ASCII diagram, lock/unlock lifecycle, where the key lives, the two documented deviations from DESIGN (in-process UI service; `vault:` link scheme) |
| `SECURITY.md` | threat model + the leak model (SPEC/00 §4), the exact sensitivity matrix (SPEC/01 §9), what is logged, what is never logged, the "no plaintext in the vault home" rule, the plain-10MB decision and its consequence, password handling (never stored, no recovery), how to verify integrity, and a short "what this design does NOT protect against" list (an attacker with the unlocked process, screen capture, clipboard) |
| `MCP.md` | how to register the bridge with Hermes (exact `hermes config set` snippet + JSON config example), the full tool/resource reference (names, params, results, error codes), locked-mode behaviour, and the tool-error convention |
| `SYNC.md` | what may be synced (the whole vault home: ciphertext + the plaintext metadata DB), what must never be synced (the runtime dir, `store.dec`), conflict behaviour (last-writer-wins on `meta.sqlite`, orphan blob GC command), and the recommendation not to run two daemons on two machines against the same synced folder |
| `IMPORT_JOPLIN.md` | the mirror layout, the mapping table, the `vault:/attachments/…` link scheme, idempotency semantics, the CLI, and the KeePass non-goal with the recommended secret-note shape |
| `WINDOWS.md` | how to build and run the portable folder, plus what is **not** tested yet (this build is produced but not verified on Windows) |
| `TESTING.md` | how to run the suites, the smoke tests, the headless daemon, the scratch-vault end-to-end recipe, and what the user must test manually (SPEC/06 §5) |

## 8. `README.md` (English, with a short Persian section at the top — the user is Persian)

Sections: one-paragraph what/why · status (implemented / not yet verified on Windows /
semantic search needs an extra) · install (`tools/bootstrap.sh`) · first run (create vault,
choose home, password — *there is no password recovery*) · quick tour (browser, editor,
sensitivity levels, secret viewer, search, log) · giving agents access (MCP registration +
what agents can and cannot do) · importing from Joplin · syncing · security notes · tests ·
repo layout · licence.

The README quickstart commands **must be the ones that actually work** (verified by running them).

## 9. `LICENSE`

GPL-3.0 **full text**. Fetch it from `https://www.gnu.org/licenses/gpl-3.0.txt`; if that is
unreachable, write the standard GPL-3.0 text; add a `SPDX-License-Identifier: GPL-3.0-only`
line to every source file header? — Decision: no per-file headers (keeps files clean); the
LICENSE file plus the README statement is enough, and `pyproject.toml`-less repo means a single
notice. (Add the licence name to `assets/icon.svg` metadata and to the About dialog.)

## 10. `TASK_SPEC.md` (repo root) + `pyproject.toml`

* `TASK_SPEC.md` = this task's master spec (SPEC/00 §5 layout) with the phase prompts.
* No `pyproject.toml` is required (the app runs from source), but include a minimal
  `pyproject.toml` with `[project] name = "secure-vault"`, version, `requires-python = ">=3.11"`,
  the runtime dependencies and `[project.scripts] secure-vault = "vault.gui:main"`,
  `secure-vault-mcp = "vault.mcp:main"` for completeness (it is not installed in this phase).
```
