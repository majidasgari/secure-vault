# Secure Vault — Architecture

This document describes the process model, the on-disk data layout, the lock/unlock
lifecycle, where the master key lives, and the two deliberate deviations from the
original Persian design (`docs/DESIGN.md`).

## 1. Process model

There is exactly **one key holder**. Everything that can decrypt data runs in a single
process; external agents only ever talk to it over a local Unix socket.

```
                       +-------------------------------------------+
                       |            GUI process (vault.gui)         |
                       |  QApplication + MainWindow                 |
   you  ──────────────►|  VaultApplication  ── Service ── VaultSession
                       |        │                  │            │
                       |        │            in-process          │
   agent (Hermes) ────►|        │                  ▼            │
        │              |        │            VaultSocketServer    |
        │  MCP stdio   |        │            (daemon.sock, 0600)  |
        ▼              |        │                  ▲            │
  +----------------+   |        │                  │            │
  | MCP bridge      |   |        │        token role "mcp"      │
  | vault.mcp       |───┼────────┘                               │
  | (stdio JSON-RPC)|   |                                       |
  +----------------+   +-------------------------------------------+
                       |  runtime: store.*.dec, daemon.sock, tokens.json
                       +-------------------------------------------+
```

* **GUI process** (`bin/secure-vault` → `python -m vault` → `vault.gui:main`). It owns
  the `VaultSession` (meta, index, blob store, encrypted content store, master key) and
  serves the socket. The UI calls the *same* `Service` in-process with `role="ui"`; it
  does not go through the socket.
* **MCP bridge** (`bin/secure-vault-mcp` → `python -m vault.mcp`). A thin, stateless
  process spawned by the agent runtime. It speaks JSON-RPC 2.0 over stdio and forwards
  every call to the socket with the `mcp` token. It never touches vault files and never
  prints anything but protocol JSON on stdout.
* **Headless daemon** (`python -m vault.daemon --home … [--unlock-file …]`). The same
  service without Qt, used by the smoke tests and for agent-only setups. `--unlock-file`
  reads the password from a `0600` file (never from argv).

If the socket is missing or refused, the bridge answers `VAULT_NOT_RUNNING`; it never
starts the GUI itself.

## 2. On-disk layout

```
<vault home>/                         e.g. /data/Cloud/SecureVault (synced)
├── .vault-meta.json                  plaintext: vault_id, KDF params + salt, canary, settings
├── meta.sqlite                       plaintext metadata: files, tags, access_log, kv
├── secure.store                      encrypted blob; plaintext is a small SQLite DB
│                                     (FTS5 content index, folder notes, embedding vectors)
└── files/
    └── <aa>/<blob_id>.enc            AES-256-GCM blob (sharded by the first 2 hex chars);
                                      files > plain_threshold (default 10 MB) are plain

<runtime dir>  $XDG_RUNTIME_DIR/secure-vault/   (fallback /tmp/secure-vault-<uid>), mode 0700
├── store.<pid>.<rand>.dec            decrypted content store, mode 0600, removed on lock
├── daemon.sock                       Unix socket, mode 0600
└── tokens.json                       {"mcp": "<64 hex chars>", "created_at": …}, mode 0600

<user config>  ~/.config/secure-vault/ui.json   language, window geometry, last vault home
```

The runtime directory is deliberately **outside** the vault home: nothing decrypted is
ever written into the synced folder. The plaintext `meta.sqlite` and `.vault-meta.json`
are the only non-ciphertext data that may live in the vault home (see
`docs/SECURITY.md` for the leak model).

## 3. Lock / unlock lifecycle

1. **Create** (`VaultSession.create`): generate Argon2id parameters and a random salt,
   derive the master key from the password, store a password-verification **canary** in
   `.vault-meta.json`, create `meta.sqlite`, create the empty `secure.store`, and open a
   `VaultFS` bound to the key. The session starts unlocked.
2. **Unlock** (`session.unlock(password)`): derive the key from the stored KDF params and
   verify it against the canary. A wrong password raises `Unauthorized("bad_password")`.
   On success, `secure.store` is decrypted to `<runtime>/store.<pid>.<rand>.dec` (mode
   `0600`) and opened; the `VaultFS` gets the key.
3. **Use**: every mutation writes the metadata row and the encrypted store in one logical
   transaction and calls `session.flush()`, which re-encrypts the content store back into
   `secure.store`. Writes are atomic (tmp + `fsync` + `os.replace`).
4. **Lock** (`session.lock()`): flush, close the store and index, **wipe the master key
   bytearray**, and delete the decrypted `store.*.dec`. While locked, metadata (names,
   levels, tags, log) is still listable, but every content operation raises
   `VaultLocked`.
5. **Auto-lock**: UI activity (`touch(source="ui")`) drives the timer; MCP activity does
   not count. `auto_lock_seconds` (default 900, `0` disables) triggers a lock.

## 4. Where the key lives

The master key is a 32-byte `bytearray` held only in the process memory of the GUI (or
headless daemon) process. It is derived on demand from the password + stored KDF params,
used to derive per-file HKDF-SHA256 keys, and zeroed by `util.wipe()` on lock. It is
never written to disk, never sent over the socket, and never logged. The socket only
accepts a **role token**, never key material, and the role (`mcp`) is bound to the token
by the server — a client cannot claim `ui`.

## 5. Deviations from `docs/DESIGN.md`

1. **In-process UI service instead of a UI-over-socket API.** The design (§8) asked for
   a local API for the UI. We implement that service layer in-process for the UI
   (`Service.dispatch(..., role="ui")`) and expose the same surface over the Unix socket
   only for agents (`role="mcp"`). This is strictly safer: the UI never needs a token,
   and agent tokens can never reach UI-only methods such as `vault.unlock`,
   `vault.read_secret`, `vault.set_settings` or `vault.verify_blobs`.
2. **The `vault:` link scheme.** The Joplin importer rewrites resource references
   (`:/<32-hex-id>`) to `vault:/attachments/<filename>` instead of a fragile relative
   path, so a note keeps working after being moved between folders. This is documented in
   `docs/IMPORT_JOPLIN.md`.

A third, smaller deviation is recorded in `docs/SECURITY.md`: files strictly larger than
10 MB are stored unencrypted (the design's own decision, §1 and §3.2), so the plaintext
leak model explicitly includes them.
