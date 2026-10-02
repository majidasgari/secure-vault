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
| browser token | `/api/autofill/*` only | **one** credential body per call, matched to the page's host | no |

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

## 2. The three calls

| route | returns | audited |
| --- | --- | --- |
| `GET /api/autofill/status` | `enabled`, `locked`, index counts (`entries`, `passwords`, `usernames`, …), `reveal_limit`, `reveals_last_minute` | one row (`vault.browser_status`) |
| `POST /api/autofill/match` `{host, url?, limit?}` | **metadata only** candidates for that host: `path`, `title`, `site`, `url`, `username`, `has_password`, `has_otp`, `score` | one row (`vault.browser_match`), no path |
| `POST /api/autofill/reveal` `{path, host}` | that entry's fields: `username`, `password`, `otp`, `url`, `title`, `site` | one row (`vault.browser_reveal`) with `target_path` |

`match` never returns a password. `reveal` is the only call that does, it is the only call that names
a path, and it refuses unless:

* the path is inside the credential root (`/رمزها`) — the root itself is not an entry;
* the entry **matches the caller's host** (`host_mismatch` otherwise) — a page cannot ask for another
  site's credentials, even knowing the path;
* the vault is **unlocked** and the bridge is **enabled**;
* fewer than `reveal_limit` reveals happened in the last rolling minute (`too_many_reveals`).

## 3. Log discipline

The index scans every credential body once and rebuilds when the tree changes. That scan is
**silent**: it reads through `quiet_scan(session)`, so a rebuild writes no per-file rows, no activity
events and no log flood. What lands in the access log is the user's actual traffic:

```
session.claim          role=browser  source=browser
vault.browser_status    role=browser  source=browser
vault.browser_match     role=browser  source=browser   (no path — the lookup is metadata)
vault.browser_reveal    role=browser  source=browser   target_path=/رمزها/…
```

`SOURCE_BROWSER` is deliberately **not** part of the transport-source list (`SOURCES`): the browser
is a distinct actor in the vault's model, and every row it produces says so.

## 4. Switch and settings

Settings → **Web UI** → *Fill credentials in the browser* (`settings["browser"]["enabled"]`,
default `on`). Switching it off makes `status` report `enabled: false` and makes `match`/`reveal`
answer `PERMISSION_DENIED` with `browser_autofill_disabled` — the add-on shows that sentence in its
popup instead of filling anything. The switch is written through the ordinary settings update
(`Service.dispatch("vault.settings.update", {"browser": {"enabled": …}})`).

## 5. Files

* `src/vault/core/credentials.py` — body parser, host normalisation/matching, the metadata index.
* `src/vault/api/browser.py` — `BrowserBridge`: token, index, status/match/reveal, rate limit.
* `src/vault/core/security.py` — `SOURCE_BROWSER`, and the read policy for that source.
* `src/vault/api/service.py` — `ROLE_BROWSER`, the `vault.browser_*` handlers.
* `src/vault/web/server.py`, `src/vault/web/api.py` — `/api/session/claim` (browser scope) and the
  `/api/autofill/*` routes, authenticated with the browser token.

## 6. Tests

```bash
./.venv/bin/python tests/run_tests.py --only browser_autofill -q     # vault side
```

`tests/test_browser_autofill.py` covers the parser, host ranking, the index, the reveal rules
(containment, host match, lock, switch, rate limit), the "scan is silent, reveal is audited"
contract, and the loopback surface: the two tokens stay separate, `/api/autofill/*` answers only the
browser token, and every reveal lands in the log with `source="browser"`.

The add-on end is exercised in a real browser by `secure-vault-browser/tests/probe.py`: it starts a
scratch vault, loads the add-on's own scripts into headless Chrome, dispatches real mouse clicks at
the icon and the entry, and then asserts both the filled fields and the vault's log rows.
