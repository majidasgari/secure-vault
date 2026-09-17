# Secure Vault — Windows portable build

The repository ships `tools/build_windows_portable.py`, which produces a self-contained
Windows folder (embeddable CPython + the runtime wheels + the app source) from this Linux
checkout. No installer and no system Python are required on the Windows side.

> **Not verified on Windows yet.** The build is produced on Linux and has never been
> executed on a real Windows machine. Treat it as a first cut and expect to fix small
> issues (paths, Qt plugins, `.cmd` quoting) when it is first run.

## 1. Offline validation (safe, no network)

```bash
./.venv/bin/python tools/build_windows_portable.py --check
```

`--check` validates the repository layout, that every third-party import in
`src/vault` is covered by `requirements.txt`, that the launchers and entry modules
exist, and that the destination is writable. It prints `CHECK OK` and exits `0`.

## 2. Building the portable folder

This mode needs the mirror (`pypi` wheel index) and `python.org` reachable:

```bash
./.venv/bin/python tools/build_windows_portable.py \
    --dest portable/win --python-version 3.12.10
```

Flags:

* `--dest PATH` — output folder (default `portable/win`; relative paths are resolved
  against the repository root).
* `--python-version X.Y.Z` — embeddable CPython version (default `3.12.10`).
* `--force` — wipe the destination before building.
* `--check` — offline validation only (above).

What the build does:

1. downloads `python-<ver>-embed-amd64.zip` from python.org and unpacks it into `--dest`;
2. enables `import site` in `python<ver>._pth` and adds `Lib\site-packages` and `src` so
   the portable `python.exe` can run the package from the folder;
3. cross-installs the `win_amd64` wheels into `Lib/site-packages` with the **host** pip:
   `pip install --target … --only-binary=:all: --platform win_amd64 --python-version …`.
   If any dependency has no wheel, pip fails and the builder **refuses to build** (it
   never compiles); it also installs `pip` into the folder the same way;
4. copies `src/`, `i18n/`, `assets/` and `bin/` into the folder;
5. writes `run.cmd`, `run.bat`, `secure-vault.cmd`, `secure-vault-mcp.cmd` and a
   Persian+English `README.txt`.

The embeddable interpreter is a Windows binary and cannot run on Linux, so step 3 uses
the host pip's cross-platform mode rather than `get-pip.py` (which would need a Windows
interpreter). This is the only way to assemble the folder on Linux and is recorded as a
deviation in the build script.

## 3. Running on Windows

1. Copy the `portable/win` folder to the Windows machine.
2. Double-click `run.cmd` (or `secure-vault.cmd`).
3. On first run, choose the vault home folder and set the master password. The password
   is never stored and cannot be recovered.
4. To give agents access, register the **absolute path** of `secure-vault-mcp.cmd` as the
   MCP server command (see `docs/MCP.md`), with `env` containing
   `SECURE_VAULT_DEBUG=1` only if you want stderr diagnostics.

The vault home is not fixed inside the portable folder; choose it on first run (the
default is a per-user location) and it is remembered in the per-user config.

## 4. What is not tested yet

* The folder has **never been run on Windows**; the `.cmd` launchers and the `_pth`
  layout are untested on a real machine.
* The wheels were cross-installed on Linux; no Windows smoke test has executed them.
* No code signing, no installer, no auto-update; SmartScreen may warn.
* Qt may require the Microsoft Visual C++ runtime, which the official PySide6 wheels
  usually bundle but which has not been verified here.
* The vault home on Windows has not been exercised with a cloud-sync client.
