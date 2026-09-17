# TASK_SPEC.md — Secure Vault (master spec + phase plan)

Self-contained implementation contract for the **Secure Vault** app in this repository.
Read `SPEC/00-overview.md` first, then the specific phase's SPEC files. `docs/DESIGN.md`
(the user's original Persian design) is the product source; the `SPEC/*` files are the
implementation contract and win on any conflict.

## Phase plan (implement in order, one phase per session; never rewrite an earlier phase's
   contracts)

| phase | scope | SPEC files | depends on |
|---|---|---|---|
| **P1** | core: errors, config, util, crypto, meta, index, vaultfs, store, security, search, semantics, session + their tests | `00`, `01`, `06` | — |
| **P2** | interfaces: service, socket server, client, MCP stdio server, headless daemon + their tests | `02`, `06` | P1 |
| **P3** | Qt UI: app, unlock, new-vault, main window, browser/models, editor, viewer, log panel, search panel, settings, tray, notifications, i18n catalogues, theme + UI smoke test | `03`, `06` | P1, P2 |
| **P4** | importers (Joplin mirror) + CLIs + smoke scripts | `04`, `06` | P1 |
| **P5** | packaging, docs, README, LICENSE, Windows builder, desktop integration | `05` | P1–P4 |

## Non-negotiables for every phase

* Implement **exactly** the file layout, module names, public signatures, error codes and JSON
  shapes written in the SPEC files. Where the SPEC is silent, choose the simplest correct thing
  and report it under "deviations" in your final message.
* stdlib + the packages in `requirements.txt` only. No new dependencies. No network access.
* `./.venv/bin/python tests/run_tests.py` must pass at the end of the phase, and the phase's own
  suites must be green (do not delete or weaken an assertion to make it pass — fix the code).
* No Persian string literals outside `i18n/*.json` (UI) — except tests/importers data.
* Never write to `/data/Cloud/SecureVault`, never touch the real Joplin mirror except read-only
  in the importer's real-mirror smoke step, and never store a password.
* Report at the end: files created/changed, the exact commands you ran with their **real**
  output tail, and a deviations list. No invented output.

## Phase prompts (the text to give the coding agent, verbatim)

**P1** — `Implement phase P1 exactly as specified in SPEC/00-overview.md, SPEC/01-core.md and
SPEC/06-tests.md (§1, §2 for the core suites). Create every module and test file those documents
name. Do not create UI, API/MCP or importer code in this phase beyond the stubs the SPEC asks
for. Verify with: ./.venv/bin/python tests/run_tests.py — every suite green. Report files,
real command output, deviations.`

**P2** — `Implement phase P2 exactly as specified in SPEC/02-interfaces.md and SPEC/06-tests.md
(§2 test_api_service, test_api_socket, test_mcp_protocol; §3 tools/smoke_mcp.py). P1 code is
already in the repo and its contracts are frozen — read it before writing. Verify with
./.venv/bin/python tests/run_tests.py and ./.venv/bin/python tools/smoke_mcp.py (both green).
Report files, real command output, deviations.`

**P3** — `Implement phase P3 exactly as specified in SPEC/03-ui.md and SPEC/06-tests.md (§2
test_ui_smoke, test_i18n). Verify with QT_QPA_PLATFORM=offscreen ./.venv/bin/python
tests/test_ui_smoke.py and ./.venv/bin/python tests/run_tests.py. Report files, real command
output, deviations.`

**P4** — `Implement phase P4 exactly as specified in SPEC/04-importers.md and SPEC/06-tests.md
(§2 test_importers, §3 smoke_e2e.py and smoke_import_real.sh). Verify with
./.venv/bin/python tests/run_tests.py, ./.venv/bin/python tools/smoke_e2e.py and
./.venv/bin/python tools/import_joplin.py --dry-run --home <scratch> --unlock-file <file>.
Report files, real command output, deviations.`

**P5** — `Implement phase P5 exactly as specified in SPEC/05-packaging.md. Verify with
./.venv/bin/python tools/build_windows_portable.py --check and the README quickstart commands,
which must actually run. Report files, real command output, deviations.`

## Current status (updated by the orchestrator, not by the coding agent)

* P1 — pending
* P2 — pending
* P3 — pending
* P4 — pending
* P5 — pending
