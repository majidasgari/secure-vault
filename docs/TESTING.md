# Secure Vault — Testing

Everything runs offline with the stdlib `unittest` framework (no pytest). Use the venv
python. All commands below are run from the repository root and were executed on this
machine unless explicitly marked as needing another environment.

## 1. Unit and invariant suites

```bash
./.venv/bin/python tests/run_tests.py
```

The runner discovers `tests/test_*.py`, runs each suite separately, prints a per-suite
summary table (`suite | tests | failures | errors | time`) and exits non-zero on any
failure. On this machine it reports **200 tests, 0 failures, 0 errors** (about 60 s).

Useful variations:

```bash
./.venv/bin/python tests/run_tests.py --only test_session    # one suite
./.venv/bin/python tests/run_tests.py -q                     # less verbose
QT_QPA_PLATFORM=offscreen ./.venv/bin/python tests/test_ui_smoke.py
```

The `test_invariants`, `test_api_invariants`, `test_ui_invariants` and
`test_real_mirror_invariants` suites wrap the orchestrator-written reference scripts in
`tests/invariants_source*.py`; they are independent adversarial checks of the security
contracts.

## 2. Smoke tests

```bash
./.venv/bin/python tools/smoke_e2e.py     # core lifecycle, prints PASS per step
./.venv/bin/python tools/smoke_mcp.py     # real daemon + real MCP bridge over stdio
```

`smoke_e2e.py` creates a scratch vault, writes notes, exercises the three searches,
requests a secret, locks, proves content is unreachable, unlocks and verifies every
blob. `smoke_mcp.py` is the acceptance test for the agent-facing contract: it starts
`python -m vault.daemon` on a scratch vault and drives `python -m vault.mcp` through the
handshake, tools, a denial, resources and the daemon-down case.

## 3. Headless daemon

The daemon runs the same service without Qt, which is useful for agents on a server or
for scripting:

```bash
printf '%s' 'scratch-password' > /tmp/sv.pw && chmod 600 /tmp/sv.pw
PYTHONPATH=src ./.venv/bin/python -m vault.daemon \
    --home /tmp/scratch-vault --unlock-file /tmp/sv.pw --json-events
```

It prints `{"event":"ready",...}` on stdout when the socket is up, logs to stderr and to
`~/.local/state/secure-vault/daemon.log`, and shuts down cleanly on SIGTERM/SIGINT.
Without `--unlock-file` it runs **locked** (metadata/status only). The `--unlock-file`
must be mode `0600`; the password is never read from argv.

## 4. Scratch-vault end-to-end recipe

To exercise the real code paths without touching your real vault:

```bash
SCRATCH="$(mktemp -d /tmp/sv-scratch-XXXX)"
printf '%s' 'scratch-password' > "$SCRATCH/pw" && chmod 600 "$SCRATCH/pw"
PYTHONPATH=src ./.venv/bin/python - <<PY
from pathlib import Path
from vault.core.session import VaultSession
home = Path("$SCRATCH/vault")
s = VaultSession.create(home, "scratch-password")
s.write_file("notes/hello.md", b"# hello\n\nscratch body\n")
s.mkdir("secrets")
s.write_file("secrets/example.md", b"password: example-only\n")
s.set_sensitivity("secrets/example.md", "secretfile")
print(s.status())
s.close()
PY
```

Then point the GUI or the importer at `$SCRATCH/vault` with the same password. Never run
these recipes against `/data/Cloud/SecureVault` unless you intend to change your real
vault.

## 5. Joplin real-mirror import (opt-in, read-only)

The importer never modifies the mirror. Run it first as a dry run, then for real, into a
**scratch** vault (not the real one):

```bash
SCRATCH="$(mktemp -d /tmp/sv-joplin-XXXX)"
printf '%s' 'scratch-password' > "$SCRATCH/pw" && chmod 600 "$SCRATCH/pw"
PYTHONPATH=src ./.venv/bin/python - <<PY
from pathlib import Path
from vault.core.session import VaultSession
VaultSession.create(Path("$SCRATCH/vault"), "scratch-password").close()
PY
./.venv/bin/python tools/import_joplin.py --home "$SCRATCH/vault" \
    --unlock-file "$SCRATCH/pw" --dry-run
./.venv/bin/python tools/import_joplin.py --home "$SCRATCH/vault" \
    --unlock-file "$SCRATCH/pw" --report docs/reports/joplin-real.md
```

The opt-in invariant suite runs the same import against the real mirror and checks
counts, fidelity, tags, attachments, link rewriting, idempotency and that the mirror was
untouched:

```bash
SECURE_VAULT_REAL_MIRROR=1 ./.venv/bin/python tests/run_tests.py --only test_real_mirror_invariants
```

## 6. Packaging checks

```bash
./.venv/bin/python tools/build_windows_portable.py --check    # prints CHECK OK
bash -n tools/bootstrap.sh tools/install-desktop.sh tools/uninstall-desktop.sh
./.venv/bin/python -m compileall -q tools
```

## 7. What the user must verify by hand

These cannot be checked headless and must be verified on the real desktop:

1. **First-run wizard**: choose the real vault home (`/data/Cloud/SecureVault`) and your
   own master password. The agent must never create the real vault or store a password.
2. **The GUI on a real screen**: Persian fonts and RTL, the KDE menu/taskbar icon, the
   tray menu, desktop notifications, and the secret-request popup arriving while the
   window is in the tray.
3. **A big real note** in the markdown preview: editing and saving, and the sync
   behaviour with your cloud folder.
4. **The importer into your real vault** (after creating it) — see `docs/IMPORT_JOPLIN.md`.
5. **MCP registration in Hermes**: ask an agent to list and search the vault
   (`docs/MCP.md`).
6. **A `secretfile`** in the native viewer, confirming an agent cannot obtain its
   content.

**Not yet verified at all:** the real GUI on a physical screen (only offscreen/headless
has been run) and the Windows portable build (produced on Linux, never run on Windows —
see `docs/WINDOWS.md`).
