# Browser autofill bridge

The vault can hand a web page's login form the user name and password of a credential stored under
`/رمزها`, the way a password-manager add-on does. This document is the contract of that bridge:
what the add-on may ask for, what the vault answers, what is written down, and what can be switched
off.

The add-on itself lives in its own repository (`secure-vault-browser`): a Firefox extension, MV3, no
build step. This document is only about the vault side.

## 1. Why a separate token

The web UI token (`runtime_dir()/web.token`) can read and write the whole vault. A browser add-on
must not hold that. So the bridge has **its own token**, minted at startup in memory, written to
`runtime_dir()/browser.token` (mode `0600`) for reference, and accepted **only** on
`/api/autofill/*`:

| token | accepted on | can read | can write |
| --- | --- | --- | --- |
| web token | `/api/*`, `/api/call` | everything the session allows | yes |
| browser token | `/api/autofill/*` only | **one** credential body per call, matched to the page's host | one credential, under the credential root, at `secretfile` level — and nothing else |

Two things follow from that table. A page that steals the browser token from the add-on still
cannot read the vault, and the browser token never appears in a URL — the add-on asks for it:

```
POST /api/session/claim
X-Vault-Claim: 1
{"scope": "browser"}          → {"ok": true, "scope": "browser", "token": …, "unlocked": …, "port": …}
```

Guards, all four required: the client address must be loopback, `X-Vault-Claim: 1` must be present,
the bridge must be attached (the web listener owns it), and the scope must be `browser`. A claim is
logged (`session.claim`, `role=browser`, `source=browser`) whether it is allowed or denied. The
token rotates with every app start, so a stale token is simply re-claimed.

## 2. The five calls

| route | returns | audited |
| --- | --- | --- |
| `GET /api/autofill/status` | `enabled`, `save_enabled`, `locked`, index counts (`entries`, `passwords`, `usernames`, …), `reveal_limit`, `reveals_last_minute`, `save_limit`, `saves_last_minute` | one row (`vault.browser_status`) |
| `POST /api/autofill/match` `{host, url?, limit?}` | **metadata only** candidates for that host: `path`, `title`, `site`, `url`, `username`, `has_password`, `has_otp`, `score` | one row (`vault.browser_match`), no path |
| `POST /api/autofill/reveal` `{path, host}` | that entry's fields: `username`, `password`, `otp`, `url`, `title`, `site` | one row (`vault.browser_reveal`) with `target_path` |
| `POST /api/autofill/save-check` `{host, username?, password?, url?, title?}` | the verdict for a credential the add-on watched being typed: `state` (`new` / `changed` / `same`), `path`, `title`, `site`, `username`, `has_otp` | one row (`vault.browser_save_check`) — **writes nothing** |
| `POST /api/autofill/save` `{host, username?, password, url?, title?, path?}` | the same shape with `saved: true` and `state` `created` / `updated` / `same` | one row (`vault.browser_save`) with `target_path` |

`match` never returns a password. `reveal` is the only call that does, it is the only call that names
a path, and it refuses unless:

* the path is inside the credential root (`/رمزها`) — the root itself is not an entry;
* the entry **matches the caller's host** (`host_mismatch` otherwise) — a page cannot ask for another
  site's credentials, even knowing the path;
* the vault is **unlocked** and the bridge is **enabled**;
* fewer than `reveal_limit` reveals happened in the last rolling minute (`too_many_reveals`).

### 2.1 The save calls (the bridge's only write)

Saving exists because a user types a password by hand on sites the vault does not know yet, and
nothing in the vault may be written without the user saying so on the page. The shape is therefore
"propose, then confirm":

* the add-on may propose **a credential**, never a destination. It sends the host (taken from the
  frame's own URL, never from page content), the typed user name and password, the page's URL and
  title. A `path` in the add-on's request is only a *hint* about which existing entry the user meant,
  and the vault re-checks it: it must live under the credential root **and** match the page's host
  (`path_not_for_host` otherwise);
* `save-check` answers what saving would mean, so the add-on can stay silent when there is nothing to
  do. **`same`** — the entry of this host and user name already holds exactly this password (a
  successful sign-in with the stored password writes nothing at all); **`changed`** — that entry
  holds another password; **`new`** — no entry matches, so saving creates one. The compare reads the
  entry's password *inside* the vault and only ever answers the verdict: no password comes back;
* `save` then either rewrites the `گذرواژه` line of that one entry — every other line, including the
  `##` notes section and a stored one-time code, is left exactly as it was — or creates a new entry
  in `مرورگر — ورودهای ذخیره‌شده` (the category the old browser export already lives in), named
  `<سایت>/<سایت>.md`, then `<سایت> (2).md`, … A file note and, for a new site folder, a folder note
  are written with it (the vault's own convention: what it is + when to reach for it). It is refused
  unless:
  * the vault is unlocked, the bridge is enabled and **saving is enabled** (`browser_save_disabled`);
  * the password is non-empty (`missing_password`) and every value fits the line-based credential
    body and the length caps (`unstorable_value`, `field_too_long`) — a newline in a password would
    silently split the label line, and storing a *wrong* password is worse than refusing;
  * fewer than `save_limit` saves happened in the last rolling minute (`too_many_saves`);
  * the request comes from **loopback**: the two save routes are the only autofill calls that also
    require a local client (`loopback_only`, `403`), so a remote holder of the token cannot write
    into the credential folder even if the listener is bound beyond `127.0.0.1`.

A user name the vault does not know is never merged into an existing entry: a different user name is
a different account, and it is created next to the first one.

## 3. Log discipline

The index scans every credential body once and rebuilds when the tree changes. That scan is
**silent**: it reads through `quiet_scan(session)`, so a rebuild writes no per-file rows, no activity
events and no log flood — and so do the reads the save path needs for its verdict (the compare must
not put the credential folder in the log). What lands in the access log is the user's actual traffic:

```
session.claim            role=browser  source=browser
vault.browser_status     role=browser  source=browser
vault.browser_match      role=browser  source=browser   (no path — the lookup is metadata)
vault.browser_reveal     role=browser  source=browser   target_path=/رمزها/…
vault.browser_save_check role=browser  source=browser   (no path — nothing is written)
vault.browser_save       role=browser  source=browser   target_path=/رمزها/…   (update)
                                                        (creation: no path in the request)
```

A real write also emits the vault's ordinary `write` activity event, with `source=browser` — so the
tray shows that something was saved.

`SOURCE_BROWSER` is deliberately **not** part of the transport-source list (`SOURCES`): the browser
is a distinct actor in the vault's model, and every row it produces says so. It is also the one
source that may **create** a file at `secretfile` level and nothing else
(`BROWSER_CREATABLE_LEVELS` in `core/security.py`): a credential must be born at the credential
level — never as a searchable `normal` file, never `secret` — and the browser may not raise an
existing file's level or lower anything at all.

## 4. Switches and settings

Settings → **Web UI** → *Fill credentials in the browser* (`settings["browser"]["enabled"]`,
default `on`). Switching it off makes `status` report `enabled: false` and makes `match`/`reveal`
answer `PERMISSION_DENIED` with `browser_autofill_disabled` — the add-on shows that sentence in its
popup instead of filling anything.

Right below it, **Settings → Web UI → Offer to save passwords from the browser**
(`settings["browser"]["save_enabled"]`, default `on`) is a second, independent switch. Switching it
off makes `status` report `save_enabled: false` and makes both save calls answer
`browser_save_disabled`; filling keeps working. The add-on also keeps, per site, the user's own
"never for this site" list — that one is the add-on's preference, not the vault's.

Both switches are written through the ordinary settings update
(`Service.dispatch("vault.settings.update", {"browser": {"enabled": …, "save_enabled": …}})`).

## 5. Files

* `src/vault/core/credentials.py` — body parser, host normalisation/matching, the metadata index, and
  the writers a browser-saved credential uses (`render_body`, `set_field`, `safe_name`, `storable`),
  which keep the file format identical to `tools/keepass-migration`'s.
* `src/vault/api/browser.py` — `BrowserBridge`: token, index, status/match/reveal, save-check/save,
  the three rate limits (`reveals`/`checks`/`saves` per minute) and the notes a new entry gets.
* `src/vault/core/security.py` — `SOURCE_BROWSER`, `BROWSER_CREATABLE_LEVELS`, and the read/raise
  policy for that source.
* `src/vault/api/service.py` — `ROLE_BROWSER`, the five `vault.browser_*` handlers.
* `src/vault/web/server.py`, `src/vault/web/api.py` — `/api/session/claim` (browser scope), the
  `/api/autofill/*` routes (browser token) and the loopback requirement on the two save routes.
* `src/vault/ui/settings_dialog.py`, `i18n/fa.json`, `i18n/en.json` — the two switches.

## 6. Tests

```bash
./.venv/bin/python tests/run_tests.py --only browser_autofill -q     # vault side
```

`tests/test_browser_autofill.py` covers the parser, host ranking, the index, the reveal rules
(containment, host match, lock, switch, rate limit), the "scan is silent, reveal is audited"
contract, the save rules (the three verdicts, the update that keeps the rest of the file, creation at
`secretfile` level in the browser category, path/host confinement, unstorable values, the save switch,
the save rate limit, the write being audited as one `vault.browser_save` row), the one policy
transition the bridge gained, and the loopback surface: the two tokens stay separate,
`/api/autofill/*` answers only the browser token, a save from off-loopback is refused while the read
routes still answer, and every real call lands in the log with `source="browser"`.

The add-on end is exercised in a real browser by `secure-vault-browser/tests/probe.py`: it starts a
scratch vault, loads the add-on's own scripts into headless Chrome, dispatches real mouse clicks at
the icon, the entry and the save bar, and then asserts both the filled fields and the vault's log
rows — including that a typed credential is offered after a sign-in that moved past its form, that a
sign-in the site rejected is never offered, that the password the vault itself filled is never
offered, and that a rejected password never reaches the add-on's storage.
