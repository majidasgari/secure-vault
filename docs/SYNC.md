# Secure Vault — Syncing the vault folder

Secure Vault does not sync anything itself. It stores all data in a single folder (the
**vault home**, default `/data/Cloud/SecureVault`) that you can put inside Dropbox,
OneDrive, Google Drive, Syncthing, etc. This document explains what is safe to sync, what
is not, and how the app behaves when two machines touch the same folder.

## 1. What may be synced

The **entire vault home** is designed to be synced:

```
<vault home>/
├── .vault-meta.json     KDF salt/params + canary (no secrets)
├── meta.sqlite          plaintext metadata: names, levels, tags, access log, kv
├── secure.store         encrypted content store (FTS index, folder notes)
└── files/<aa>/<blob>.enc   AES-256-GCM blobs (or plain blobs > 10 MB)
```

The semantic vector cache is **not** here by default: it lives in the user's data dir
(`$XDG_DATA_HOME/secure-vault/semantic/<vault_id>.db`, i.e. under the user's home), which
is outside the synced folder. See §2.

Everything except the metadata DB is ciphertext. The metadata DB and `.vault-meta.json`
are plaintext by design (see `docs/SECURITY.md`); they leak names, levels, tags and the
access log, but no content.

## 2. What must never be synced

* The **runtime directory** `$XDG_RUNTIME_DIR/secure-vault/` (fallback
  `/tmp/secure-vault-<uid>/`), which contains:
  * `store.<pid>.<rand>.dec` — the **decrypted** content store;
  * `daemon.sock` — the local Unix socket;
  * `tokens.json` — the per-daemon MCP token.
* The **semantic vector cache** — encrypted, but a **derived, rebuildable cache**, not
  data. It lives under the user's home by default (Settings → Semantic shows and lets you
  change the path), so it is never swept up by the cloud client; each machine rebuilds it
  locally (Settings → Semantic → *Build/refresh index*). If you point it at a path inside
  the vault home, exclude it from sync by name. It can be large (one vector per chunk) and
  is never worth syncing.
* The **embedding cache** `~/.local/share/secure-vault/semantic/cache/<model>__<dim>.db`
  (`$XDG_DATA_HOME`) — unencrypted, content-addressed vectors, rebuildable on demand and
  never worth syncing or backing up (Settings → Semantic → *Clear vector cache*).
* The user config `~/.config/secure-vault/ui.json` (machine-local window state).
* Any backup or export you make outside the vault home.

The runtime directory is outside the vault home precisely so it is never swept up by the
cloud client. Never copy `store.*.dec` or `semantic.*.dec` anywhere.

> Rebuilding the semantic index needs the embedding model available locally and downloads
> it once (see `requirements-semantic.txt`). Until it is rebuilt, semantic search simply
> returns nothing on that machine; full-text and filename search keep working.

## 3. Conflict behaviour

* **`files/*.enc` blobs** are effectively immutable: a content change writes a *new*
  random `blob_id`, and the old blob is deleted only after the metadata row is updated.
  Two machines editing different files therefore never collide at the blob level.
* **`meta.sqlite` and `secure.store` are single files**, so a cloud client resolves
  concurrent changes with its usual **last-writer-wins** policy. If two machines edit the
  vault while both are unlocked, one machine's index/store can overwrite the other's; the
  losing machine's blobs may still exist on disk but become unreferenced.
* The SQLite databases use WAL mode; cloud clients do not understand WAL and may sync
  `-wal`/`-shm` side files inconsistently. Prefer to let a sync finish while the app is
  **locked**, when no writes are in flight.
* A note removed on one machine is never deleted from the vault by the Joplin importer;
  ordinary deletes are explicit UI/agent actions.

### Cleaning up orphan blobs

After a conflict, `files/` can contain blobs no longer referenced by `meta.sqlite`. The
app exposes a garbage collector in the core (`VaultFS.gc_orphans`); run it from a shell
while the vault is unlocked, with the app closed on every other machine:

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

This only ever deletes files under `files/` that no metadata row references; it never
touches the metadata DB or the store.

## 4. Recommendation: one daemon at a time

Do **not** run two daemons (two GUI instances or a GUI plus a headless daemon) on two
machines against the same synced folder at the same time. The design is single-writer:
one process owns the key and the content store, and the socket/token are per-machine.
Use one machine as the writer, let the cloud client finish, then unlock on the other.
If you need read-only access elsewhere, lock the vault first.
