# Secure Vault — running and building on Windows

Windows is a **supported second platform**, not a port-in-progress. Everything the app
needs is in the standard library plus the packages in `requirements.txt`; nothing is
compiled, and the same source tree runs unchanged on Linux and Windows.

* **Verified on Windows 10** (x86-64, Python 3.12.10, PySide6 6.11.2):
  `tests/run_tests.py` green, the portable build produced by
  `tools/build_windows_portable.py`, and `python.exe -m vault --self-test` running **from
  inside the built folder** (prints `SELFTEST OK`).
* Verified on POSIX (Linux) as before — the Windows support is additive: every platform
  branch falls back to the exact previous behaviour when `AF_UNIX`/`fcntl`/POSIX modes are
  available.

## 1. What differs on Windows

| Concern | POSIX (Linux/macOS) | Windows |
|---|---|---|
| Daemon transport | Unix-domain socket (`runtime_dir/daemon.sock`) | **Loopback TCP** on `127.0.0.1` with an ephemeral port — CPython has no `AF_UNIX` there |
| Endpoint discovery | the socket path | `runtime_dir/endpoint.json` (`{"kind":"tcp","host":…,"port":…}`), written by the daemon |
| Authentication | `mcp` token in `tokens.json` (0600) | **identical** (the token is the door, so TCP is no wider than the socket) |
| Single instance (GUI) | `flock` on `<runtime>/gui.lock` | named mutex `Local\secure-vault-gui-<hash>` |
| "Is this pid alive?" | `os.kill(pid, 0)` | `OpenProcess` + `GetExitCodeProcess` (`os.kill` on Windows would *kill* the process) |
| File modes | real `0600`/`0700` bits | none — protection is the per-user ACL of `%LOCALAPPDATA%`/`%APPDATA%` |
| Fingerprint quick unlock | `fprintd` CLI | not available; `device_info` reports `fprintd_missing` and the feature stays off |
| Session log | `~/.local/state/secure-vault/daemon.log` | `%LOCALAPPDATA%\secure-vault\state\daemon.log` |

Directories (the `XDG_*` variables still win when you set them, which is what the test
suite and portable copies use):

| What | Windows | POSIX default |
|---|---|---|
| Vault home (default) | `%USERPROFILE%\Documents\SecureVault` | `/data/Cloud/SecureVault` |
| Runtime (store, endpoint, tokens) | `%LOCALAPPDATA%\secure-vault\runtime` | `$XDG_RUNTIME_DIR/secure-vault` or `/tmp/secure-vault-<uid>` |
| Config (`ui.json`, `s3.json`) | `%APPDATA%\secure-vault` | `~/.config/secure-vault` |
| Data (vector/embedding cache) | `%LOCALAPPDATA%\secure-vault` | `~/.local/share/secure-vault` |
| Logs | `%LOCALAPPDATA%\secure-vault\state` | `~/.local/state/secure-vault` |

`SECURE_VAULT_HOME` overrides the vault home on both platforms; the first-run wizard lets
you pick a folder, and the choice is remembered in `ui.json`.

**No POSIX mode bits.** `os.chmod` on Windows only toggles the read-only flag, so every
"is it 0600?" assertion is POSIX-only (`tests/support.py: assert_private_mode`) and the
equivalent guarantee on Windows is the ACL of the per-user directories above — keep the
runtime and config directories inside your own profile (they are by default).

**Closing the app.** A clean exit (tray → *Quit*, or a POSIX `SIGTERM`) removes the socket,
`endpoint.json` and `tokens.json`. Windows has no deliverable termination signal, so a
force-kill (`taskkill /F`, or `terminate()` in the tests/tools) skips that cleanup and
leaves a stale `endpoint.json` pointing at a dead port; the next start overwrites it, and a
client that finds a dead or foreign port is answered with `VAULT_NOT_RUNNING` or
`UNAUTHORIZED` rather than a wrong result.

## 2. Running from a checkout

```bash
uv venv --python 3.12 .venv                 # or: python -m venv .venv
uv pip install --python .venv/Scripts/python.exe -r requirements.txt
```

Then either:

```bat
bin\secure-vault.cmd                        :: GUI (double-clickable)
bin\secure-vault-mcp.cmd                    :: MCP stdio bridge (for agents)
bin\secure-vault-web.cmd --home D:\Vault --port 8788
```

The three launchers detect their layout: a sibling `python.exe` (the portable build), else
`..\.venv\Scripts\python.exe` (a checkout), else `python` on `PATH`. The same files are
therefore correct inside `portable\win\bin\` too, and either of these starts the portable
app:

```bat
portable\win\secure-vault.cmd
portable\win\bin\secure-vault.cmd
```

or the module form, which is what the launchers call:

```bash
set PYTHONPATH=%CD%\src
.venv\Scripts\python.exe -m vault
```

`tools/bootstrap.sh` is a bash script (git-bash/WSL works); on native Windows the four
commands above are the whole story. The `.cmd` launchers fall back to `python` on `PATH`
when `.venv` does not exist.

Headless check (no window, no display server needed):

```bash
set QT_QPA_PLATFORM=offscreen
.venv\Scripts\python.exe -m vault --self-test      # prints SELFTEST OK + a JSON report
```

## 3. Building the portable folder

```bash
.venv\Scripts\python.exe tools\build_windows_portable.py --check
.venv\Scripts\python.exe tools\build_windows_portable.py --dest portable\win --force
```

* `--check` validates the layout, that every third-party import is covered by
  `requirements.txt`, and that the destination is writable. It prints `CHECK OK`.
* The real build downloads `python-3.12.10-embed-amd64.zip` from python.org, enables
  `import site` in `python312._pth`, cross-installs the `win_amd64` wheels (plus `pip`) into
  `Lib\site-packages` with `pip --only-binary=:all:`, copies `src/ i18n/ assets/ bin/` and
  writes `run.cmd`, `run.bat`, `secure-vault.cmd`, `secure-vault-mcp.cmd` and a
  Persian+English `README.txt`.
* **The build interpreter needs `pip`.** A `uv venv` does not ship one; install it first
  (`uv pip install --python .venv\Scripts\python.exe pip`). The builder says so instead of
  failing obscurely.
* The result is ~700 MB and self-contained: no system Python, no installer. Double-click
  `run.cmd`. Verify it the same way the release was verified:

```bash
cd portable\win
set PYTHONPATH=
set QT_QPA_PLATFORM=offscreen
python.exe -m vault --self-test            # SELFTEST OK
```

Semantic search is an **opt-in extra** (`requirements-semantic.txt`: `sentence-transformers`
+ `sqlite-vec`) and is deliberately *not* in the portable folder — it is large and
rebuildable. Without it the self-test reports
`"semantic_index": "skipped: ProviderUnavailable…"` and every other feature works; install
the extra with `pip install -r requirements-semantic.txt` if you want it.

## 4. Giving agents access (MCP) on Windows

The bridge is `bin\secure-vault-mcp.cmd` (or `portable\win\secure-vault-mcp.cmd`). It finds
the running app through `runtime_dir\endpoint.json`, so on Windows it needs no socket path.
Register it with Hermes using the **absolute** path:

```json
{
  "mcp_servers": {
    "secure-vault": {
      "command": "D:\\Codes\\Personal\\secure-vault\\bin\\secure-vault-mcp.cmd",
      "args": []
    }
  }
}
```

Explicit credentials also work and are transport-agnostic:

```bash
secure-vault-mcp.cmd --endpoint 127.0.0.1:51234 --token <token>
# or via the environment: SECURE_VAULT_ENDPOINT=127.0.0.1:51234 SECURE_VAULT_TOKEN=…
```

The app must be running and unlocked, otherwise the tools answer `VAULT_NOT_RUNNING` /
`VAULT_LOCKED`. `SECURE_VAULT_DEBUG=1` puts diagnostics on stderr (stdout stays pure
JSON-RPC).

## 5. What still needs a human

* The GUI, tray, notifications, fonts and RTL layout on a real screen (the automated
  self-test runs `QT_QPA_PLATFORM=offscreen`, which exercises the flows but paints nothing).
* Code signing / SmartScreen: the portable folder is unsigned, so Windows will warn the
  first time (that is expected for an unsigned personal build).
* A fingerprint reader — there is no `fprintd` on Windows, so quick unlock stays disabled;
  the wrapped-key record format itself is platform-independent.
* S3/cloud-drive sync against a real remote on Windows (`test_sync` covers the protocol
  with a fake server).
* Two vault processes (the GUI and the web UI) against one runtime directory: the
  second-instance guard is the named mutex, which is per-user session.
