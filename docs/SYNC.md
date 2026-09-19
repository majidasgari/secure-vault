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

## 8. Recommendation

Keep the lock discipline: one writer, the others read-only, sync before you switch
machines. The built-in S3 sync plus the lock is the supported path; the cloud-drive
recipe is only a fallback.
