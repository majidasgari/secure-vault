# Secure Vault — Syncing the vault folder

Secure Vault stores everything in a single folder (the **vault home**, default
`/data/Cloud/SecureVault`). It can mirror that whole folder to any S3-compatible bucket
(AWS S3, MinIO, Backblaze B2 via its S3 API, …) with a built-in two-way sync and a
cooperative write lock, or you can sync the folder yourself with Dropbox/OneDrive/Google
Drive/Syncthing. This document covers both.

## 0. The one rule: only one writer at a time

`files/`, `secure.store` and `meta.sqlite` are **not** designed to merge. The built-in
sync therefore uses a **lock object** in the bucket (`.secure-vault.lock`):

* When the vault is unlocked, the client tries to acquire the lock.
* If another client holds it, this session becomes **read-only**: every write (edit,
  create, move, delete, note, tag, level change, search-index rebuild) is refused.
* The **Take write access** button forces the lock to this device (use it after a crash
  or when you know the other device is gone). It overwrites the lock object.
* On lock/quit the client releases the lock so the other device can take over.

The lock is a plain JSON object (`owner`, `host`, `pid`, `acquired_at`, `heartbeat_at`);
the credentials are never in it.

## 1. Enabling S3 sync

No extra package is required: the app signs requests itself with AWS SigV4 over
`http.client`. (`requirements-s3.txt` offers `boto3` as an optional alternative backend
when it is available; the two are interchangeable.)

1. Open **Settings → S3 sync** and fill in the bucket, optional prefix (folder in the
   bucket), endpoint URL (for non-AWS providers) and region. Tick *Sync this vault with
   S3* and enter the access key/secret.

   * The bucket/prefix/endpoint/region are stored in the vault settings (they are
     coordinates, not secrets).
   * The **access key and secret are stored machine-locally** in
     `~/.config/secure-vault/s3.json` (mode `0600`) and are **never** written into the
     vault, so they cannot leak through the cloud client.

2. Press **Sync now**. On the first run everything is uploaded; later runs only transfer
   changed files.

## 2. Locking and read-only mode in practice

* **Unlocking** a synced vault does not make it writable until the lock is acquired. If
  the bucket is unreachable or held by another device, the app opens read-only — this is
  deliberate: refusing to write is always safer than overwriting a peer's work.
* The status bar shows `S3: synced`, `S3: read-only`, `S3: off` or `S3: error`. The web
  UI shows a red read-only banner naming the holder.
* Use **Take write access** (Tools menu / tray / web banner / Settings tab) to force the
  lock to this device.
* Sync is refused while read-only, so run it after taking access.

## 3. What is synced (and what never is)

The **entire vault home** is synced:

```
<vault home>/
├── .vault-meta.json     KDF salt/params + canary (no secrets)
├── meta.sqlite          plaintext metadata: names, levels, tags, access log, kv
├── secure.store         encrypted content store (FTS index, folder/file notes)
└── files/<aa>/<blob>.enc   AES-256-GCM blobs (or plain blobs > 10 MB)
```

Never synced (excluded by the engine even if they end up in the folder):

* **Semantic vectors** — `semantic*.db` / any `*.db`. They are derived data and live
  outside the vault by default (`$XDG_DATA_HOME/secure-vault/semantic/`). Settings
  refuses to store a vector-cache path inside the vault home.
* **Embedding cache** — `*.db` under the user data dir (see §6).
* Runtime leftovers (`*.dec`, `store.*`, `*.tmp`, `*.sqlite-wal`, `*.sqlite-shm`,
  `.DS_Store`, the lock object itself).

The runtime directory (`$XDG_RUNTIME_DIR/secure-vault/` or `/tmp/secure-vault-<uid>/`)
holds the decrypted store, the socket and the token; it is outside the vault and is
never uploaded. Never copy `store.*.dec` anywhere.

## 4. How the mirror resolves changes

The sync is three-way: it compares the local files, the bucket and a machine-local
manifest of the last successful sync (`$XDG_DATA_HOME/secure-vault/sync/<vault>.json`).

* New/changed on one side → transferred to the other side.
* Deleted on one side → deleted on the other (this is why the manifest is kept).
* Changed on both sides at once → the local writer wins and the path is reported in
  `conflicts`; this should not happen while the lock works correctly.
* `.sqlite` WAL is checkpointed into `meta.sqlite` before upload so the single file is
  self-contained; `-wal`/`-shm` side files are never uploaded.

`meta.sqlite` grows one access-log row per call, so two syncs in a row may each upload a
changed `meta.sqlite`; large content is only transferred once.

A request carrying a large body gets a longer socket timeout (300 s instead of 15 s):
secure.store grows with the search index (tens of megabytes is normal) and a slow link
would otherwise abort the upload mid-way — which looks exactly like a sync that stopped
halfway through with the store as the last file left behind.

## 5. Sync from the app or the web

* **Desktop app**: Tools → *Sync now* (`menu.sync`), the tray *Sync now* action, or the
  **Sync now** button on **Settings → S3 sync**. A notification reports the counts.
* **Web UI**: the **Sync** button in the header. A read-only banner appears with a
  **Take write access** button when another device holds the lock.

The sync runs in a **background thread** and never holds the service lock, so the app and
the browser stay responsive. Both show live progress (uploaded/downloaded/deleted
counters and the current path) while it runs, and writes are refused with
`sync_in_progress` until it finishes (no half-written vault). Locking the vault cancels a
running sync.

**Test connection**: *Settings → S3 sync → Test connection* lists the bucket and reports
whether the endpoint, bucket and credentials are correct, without transferring anything.
It is also available over the API as `vault.sync_test`.

## 6. Moving the embedding cache to a flash drive (no re-embedding)

The paragraph→vector cache is **content-addressed** and keys vectors by
`HMAC(salt, model|dim|normalizer_version|sha256(text))`. The salt lives inside each cache
database, so moving a cache file intact keeps every key valid and the system reuses the
vectors instead of recomputing them.

Manual recipe:

1. Close Secure Vault (or at least stop indexing) on both machines.
2. Copy the whole per-model cache file, not just part of it:

   ```bash
   mkdir -p /media/flash/secure-vault-cache
   cp ~/.local/share/secure-vault/semantic/cache/*.db* /media/flash/secure-vault-cache/
   ```

   (The filename encodes the model and dimension, e.g.
   `BAAI__bge-m3__1024.db`. Copy the `-wal`/`-shm` siblings too if present.)
3. On the machine that should use the moved cache, point `XDG_DATA_HOME` at the flash
   (or copy the file back to `~/.local/share/secure-vault/semantic/cache/`). The cache
   directory is `<XDG_DATA_HOME>/secure-vault/semantic/cache/`.

Because the key includes the model, the dimension and the normalizer version, a cache is
only reused by a matching model; changing chunking mode (paragraph ↔ sentence ↔
document) does **not** invalidate it. If the salt is missing or the file is corrupted,
the affected entries are simply re-embedded (a cache miss), never an error.

The cache holds only derived vectors (no vault content), is unencrypted on purpose,
and is **never synced** — moving it by hand is the supported way to avoid paying the
embedding cost again. You can clear it from **Settings → Semantic search → Clear vector
cache**.

## 7. Alternative: cloud-drive sync (no built-in client)

If you prefer a Dropbox/Drive client, put the vault home inside it and follow the same
single-writer rule. The old caveats still apply:

* Do **not** run two daemons against the same synced folder on two machines at the same
  time.
* Prefer to let a sync finish while the app is **locked**.
* `meta.sqlite` and `secure.store` are single files: a cloud client resolves concurrent
  changes last-writer-wins, so one side's changes can be lost.

### Cleaning up orphan blobs

After a conflict, `files/` can contain blobs no longer referenced by `meta.sqlite`. The
core exposes `VaultFS.gc_orphans`; run it from a shell while the vault is unlocked, with
the app closed on every other machine:

```bash
read -r -s -p "master password: " SV_PW; echo
SV_PW="$SV_PW" PYTHONPATH=src ./.venv/bin/python - <<'PY'
import os
from pathlib import Path
from vault.core.session import VaultSession

home = Path("/data/Cloud/SecureVault")          # your vault home
session = VaultSession(home)
session.unlock(os.environ["SV_PW"])
removed = session.fs.gc_orphans()
session.flush()
session.close()
print(f"removed {removed} orphan blob(s)")
PY
```

This only deletes files under `files/` that no metadata row references.

## 8. Restoring a vault that is already in the bucket

**Never create an empty vault and sync it onto a bucket that already holds one.** The two
vaults have different `vault_id` values and different KDF salts, so the new vault's empty
index and fresh identity would replace the bucket's — every blob survives, but the index
that names them is gone, and the old identity (the salt that decrypts those blobs) is
overwritten too. Sync now refuses that case (§9), and the supported way to bring such a
vault back is to **restore it**:

* **Desktop app** — *Restore from S3…* on the unlock screen. Fill in the bucket, prefix,
  endpoint/region and the keys (pre-filled from the machine-local credentials after the
  first use), optionally the vault's master password, then press **Check the bucket** to see
  exactly what is there before anything is written.
* **Headless** — `secure-vault-import` (or `python -m vault.import_cli`):

  ```bash
  secure-vault-import --home /data/Cloud/SecureVault --bucket my-bucket --prefix sync \
      --endpoint https://s3.ir-thr-at1.arvanstorage.ir --region ir-thr-at1 --check
  secure-vault-import --home /data/Cloud/SecureVault --bucket my-bucket --prefix sync \
      --endpoint https://s3.ir-thr-at1.arvanstorage.ir --region ir-thr-at1
  ```

The restore adopts the bucket's own files:

```
.vault-meta.json   identity: vault id, KDF salt, canary, settings  -> unlock with the ORIGINAL password
meta.sqlite        the index (names, paths, levels, tags, history)
secure.store       the encrypted content store (folder notes, FTS index)
files/**           the blobs the index references
```

Rules it follows, all of them designed so a failure can never cost data:

* **Blobs are reused, not re-downloaded.** A blob whose file is already present with the
  same size is skipped, so restoring next to an existing `files/` folder (the usual
  recovery case) transfers only the metadata.
* **The index is verified before it is installed.** Every blob the index references must be
  present after the download, otherwise the import stops with `import_incomplete` and does
  **not** install anything — a vault that lists files it cannot decrypt is worse than no
  vault at all.
* **The identity is installed last.** Until `.vault-meta.json` exists the folder is not a
  vault, so an interrupted restore can never be mistaken for a usable (or lockable) one.
* **The password is checked first.** When you type it, it is verified against the canary in
  the bucket *before* the first byte is downloaded.
* **An existing vault is parked, never deleted.** Restoring into a folder that already
  holds a *different* vault asks first; its metadata files move to
  `<folder>.replaced-<stamp>/` (with a short `README.txt`) and its `files/` blobs stay where
  they are so the restore can reuse them. Unreferenced leftovers can be pruned later with
  `VaultSession.fs.gc_orphans` (§7).
* **The sync base is seeded.** The restored folder is recorded as the last-synced manifest,
  so the first sync after a restore transfers only what really changed.

## 9. Safety rails on sync

Three rules keep the mirror from destroying the other side. All three fire *before* anything
is transferred.

1. **Identity guard.** If the bucket already holds a `.vault-meta.json` with a different
   `vault_id` than this vault, the sync stops with `vault_id_mismatch` and names both ids.
   Two vaults are not a merge; use *Restore from S3* (§8) to adopt the bucket's vault, or
   point this vault at its own prefix.
2. **No clobbering a richer remote index.** An upload that would replace a remote
   `meta.sqlite`/`secure.store`/`.vault-meta.json` with a file smaller than a quarter of it
   (and the remote one is at least 1 MB) stops with
   `refusing_to_overwrite_remote_metadata`. This is what an empty "just created" vault looks
   like to a bucket that holds years of notes. Deliberate mass deletions can opt out with the
   vault setting `sync.allow_metadata_overwrite: true`.
3. **A copy before every overwrite.** Before a sync overwrites a metadata file whose remote
   content differs, the current object is copied to
   `<prefix>/.secure-vault-backups/<utc stamp>/<name>` (the newest
   `META_BACKUP_KEEP` = 3 generations per file are kept; objects over 8 MB — the encrypted
   store — are skipped). The folder is never mirrored into the vault, so it is a plain
   rollback source: download the object and put it back if a sync ever goes wrong.

Both guards report their reason in the notification/status line in the UI language
(`sync.reason.<code>` in `i18n/*.json`).

## 10. Recommendation

Keep the lock discipline: one writer, the others read-only, sync before you switch
machines. The built-in S3 sync plus the lock is the supported path; the cloud-drive
recipe is only a fallback.
