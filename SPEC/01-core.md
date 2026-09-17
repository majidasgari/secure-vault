# SPEC 01 — Core layer (crypto, metadata, vault FS, secure store, policy, search)

Package `src/vault/`. Modules in this file: `vault/errors.py`, `vault/config.py`,
`vault/util.py`, `vault/core/{crypto,meta,vaultfs,index,store,security,search,semantics,session}.py`.

All of these must be usable **without Qt** (the tests import them headless, and the headless
daemon runs without any GUI import).

---

## 1. `vault/errors.py`

```python
class VaultError(Exception):
    code: str = "ERROR"
    def __init__(self, message: str, *, details: dict | None = None): ...
    def to_dict(self) -> dict          # {"code": ..., "message": ..., "details": {...}}

class VaultLocked(VaultError):         code = "VAULT_LOCKED"
class VaultNotRunning(VaultError):     code = "VAULT_NOT_RUNNING"
class PermissionDenied(VaultError):    code = "PERMISSION_DENIED"
class DowngradeForbidden(VaultError):  code = "SENSITIVITY_DOWNGRADE_FORBIDDEN"
class NotFound(VaultError):            code = "NOT_FOUND"
class AlreadyExists(VaultError):       code = "ALREADY_EXISTS"
class InvalidPath(VaultError):         code = "INVALID_PATH"
class TamperDetected(VaultError):      code = "TAMPER_DETECTED"
class BadRequest(VaultError):          code = "BAD_REQUEST"
class Unauthorized(VaultError):        code = "UNAUTHORIZED"
class ProviderUnavailable(VaultError): code = "PROVIDER_UNAVAILABLE"
```

## 2. `vault/config.py`

```python
DEFAULT_VAULT_HOME = "/data/Cloud/SecureVault"     # overridable by env SECURE_VAULT_HOME
DEFAULT_PLAIN_THRESHOLD = 10 * 1024 * 1024         # files strictly larger than this are stored plain
DEFAULT_AUTO_LOCK_SECONDS = 900                    # 0 disables auto-lock
DEFAULT_LANGUAGE = "fa"
def runtime_dir() -> Path      # $XDG_RUNTIME_DIR/secure-vault (fallback /tmp/secure-vault-<uid>), mode 0700
def user_config_dir() -> Path  # $XDG_CONFIG_HOME/secure-vault  (fallback ~/.config/secure-vault)
def user_config() -> UserConfig          # load/save ui.json: {"language", "window": {...}, "last_folder"}
def app_paths() -> AppPaths              # dataclass: repo_root, assets_dir (fonts/icon), i18n_dir
```

`user_config` is written atomically. It is the only file allowed outside the vault home and
the runtime dir. Unknown keys in `ui.json` are preserved (forward compatible).

## 3. `vault/util.py`

- `atomic_write_bytes(path: Path, data: bytes) -> None` — tmp in same dir, `os.fsync`, `os.replace`.
- `normalize_logical_path(raw: str) -> str` — NFC, strip, convert `\` → `/`, collapse `//`,
  reject absolute paths, reject any `..` segment, reject empty, reject control chars
  (`< 0x20`) and NUL; length ≤ 1024 bytes; returns the canonical POSIX relative path.
  Raises `InvalidPath`.
- `normalize_fa(text: str) -> str` — Persian search normalization, applied to **both** indexed
  text and queries: `ي→ی`, `ك→ک`, `ۀ→ه`, `ة→ه`, `أإآ→ا`, strip diacritics `U+064B..U+0652`,
  `U+0670`, `U+0640` (tatweel); Persian/Arabic digits `۰-۹ ٠-٩` → ASCII `0-9`; collapse runs of
  whitespace to a single space; keep ZWNJ (`U+200C`) as-is.
- `human_size(n: int) -> str`, `now_ms() -> int`, `sha256_hex(data: bytes) -> str`.
- `wipe(buf: bytearray) -> None` — overwrite with zeros (best effort).

## 4. `vault/core/crypto.py`

File blob format (all integers big-endian):

```
offset  size  field
0       4     magic  b"SVLT"
4       1     format version = 1
5       1     kdf id   (1 = argon2id, 2 = pbkdf2-sha512)
6       1     flags    (bit0 = plain, reserved bits 0)
7       1     reserved = 0
8       16    per-file salt (HKDF salt; random; unused when flags.plain)
24      12    nonce (unused when plain)
36      ...   ciphertext||tag   (or the raw bytes when plain)
```

API:

```python
class KdfParams(NamedTuple):        # stored in .vault-meta.json
    algo: str                        # "argon2id" | "pbkdf2-sha512"
    salt: bytes                      # 16 bytes
    time_cost: int                   # argon2id: 3
    memory_kib: int                  # argon2id: 262144
    parallelism: int                 # argon2id: 4
    iterations: int                  # pbkdf2: 600000

def available_kdf() -> str                     # "argon2id" if argon2 importable else "pbkdf2-sha512"
def new_kdf_params() -> KdfParams              # uses available_kdf(); random salt
def derive_master_key(password: str, params: KdfParams) -> bytearray   # 32 bytes
def derive_file_key(master_key: bytes, blob_id: str, salt: bytes) -> bytes
    # HKDF-SHA256(ikm=master_key, salt=salt, info=b"secure-vault/file/" + blob_id.encode())
def encrypt_blob(master_key, blob_id: str, data: bytes, *, sensitivity: str,
                 plain: bool = False, kdf_id: int = 1) -> bytes
def decrypt_blob(master_key, blob_id: str, blob: bytes, *, sensitivity: str) -> bytes
def is_plain_blob(blob: bytes) -> bool
def make_canary(master_key) -> bytes           # encrypt_blob(master_key, "canary", b"secure-vault", sensitivity="normal")
def check_canary(master_key, canary: bytes) -> bool    # False on TamperDetected, never raises to caller
```

Rules:
- **AAD** = `b"sv/" + blob_id.encode() + b"/" + sensitivity.encode()`. Decryption with a
  different `blob_id` or `sensitivity` **must** raise `TamperDetected` (test covers this).
- Any `InvalidTag`/malformed header/unsupported version → `TamperDetected`; short/garbage input
  → `TamperDetected` (never a raw `OSError`/`ValueError` escaping).
- `plain=True` still writes the header (flags.plain) and stores the payload unencrypted; such
  a blob decrypts only when `plain` is expected. Plain blobs must still be listed and readable
  when the vault is **locked**? No — keep it simple and safe: plain blobs are readable only
  through the unlocked session, like everything else (documented in SECURITY.md).
- Keys are `bytearray` and wiped by the session on lock.
- Password strings are never logged and never stored. The session keeps the derived key only.

## 5. `vault/core/meta.py` — `.vault-meta.json` (plaintext, in the vault home)

```json
{
  "schema_version": 1,
  "vault_id": "<uuid4>",
  "created_at": 1750000000000,
  "kdf": {"algo": "argon2id", "salt_b64": "...", "time_cost": 3, "memory_kib": 262144,
          "parallelism": 4, "iterations": 600000},
  "canary_b64": "...",
  "settings": {
    "plain_threshold_bytes": 10485760,
    "auto_lock_seconds": 900,
    "default_sensitivity": "normal",
    "semantic": {"enabled": false, "model": "all-MiniLM-L6-v2", "provider": "local"},
    "import_joplin": {"mirror_root": "/data/Cloud/Documents/Notes/joplin-mirror",
                      "sensitive_globs": []}
  }
}
```

```python
class VaultMeta:
    @classmethod def create(cls, path: Path, password: str) -> "VaultMeta"    # writes the file
    @classmethod def load(cls, path: Path) -> "VaultMeta"                     # SchemaTooNew → BadRequest
    def save(self) -> None                                                    # atomic
    def kdf_params(self) -> KdfParams
    @property settings(self) -> dict                                          # mutable, call save()
    def verify_password(self, password: str) -> bool                          # via canary
    def rekey(self, new_password: str) -> None     # not required in P1; raise NotImplementedError with a clear message
```
A missing/invalid `.vault-meta.json` → `NotFound("vault_not_initialised")`.

## 6. `vault/core/index.py` — `meta.sqlite` (plaintext metadata DB)

Plaintext on purpose (names/levels are visible while locked, per design §12). **No file
content, no folder-note text, no FTS rows in this DB** — enforced by tests that scan it.

```sql
PRAGMA journal_mode=WAL;  PRAGMA foreign_keys=ON;
CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT);            -- 'schema_version' = '1'
CREATE TABLE files(
  id INTEGER PRIMARY KEY,
  logical_path TEXT NOT NULL UNIQUE COLLATE NOCASE,
  blob_id TEXT,                      -- NULL for directories
  is_dir INTEGER NOT NULL DEFAULT 0,
  size INTEGER NOT NULL DEFAULT 0,
  encrypted INTEGER NOT NULL DEFAULT 1,     -- 0 for plain (>threshold) blobs
  sensitivity TEXT NOT NULL DEFAULT 'normal' CHECK(sensitivity IN ('normal','secret','secretfile')),
  mtime INTEGER NOT NULL, created INTEGER NOT NULL,
  source TEXT NOT NULL DEFAULT 'ui'          -- ui | mcp | importer
);
CREATE INDEX idx_files_parent ON files(logical_path);
CREATE TABLE tags(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE file_tags(file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                       tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
                       PRIMARY KEY(file_id, tag_id));
CREATE TABLE access_log(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL,
  role TEXT NOT NULL, tool TEXT NOT NULL, target_path TEXT, outcome TEXT NOT NULL,
  code TEXT, details TEXT, session TEXT);     -- append-only; nothing ever updates/deletes it
CREATE TABLE kv(key TEXT PRIMARY KEY, value TEXT);   -- importer bookkeeping, settings mirrors
```

```python
class Index:
    def __init__(self, path: Path): ...            # creates/migrates on first use
    def close(self) -> None
    # files
    def upsert_file(self, logical_path, *, blob_id=None, is_dir=False, size=0, encrypted=1,
                    sensitivity="normal", mtime=None, created=None, source="ui") -> int
    def get_file(self, logical_path) -> dict | None
    def require_file(self, logical_path) -> dict          # NotFound
    def delete_file(self, logical_path, *, recursive=False) -> list[dict]  # returns removed rows
    def list_dir(self, logical_path) -> list[dict]        # direct children, dirs first, name-sorted
    def walk(self, logical_path="/")  -> Iterator[dict]
    def move(self, src, dst) -> None                      # also rewrites descendants' paths
    def count(self) -> dict            # {"files": n, "dirs": n, "by_level": {...}}
    # levels
    def set_sensitivity(self, logical_path, level) -> None
    def sensitive_paths(self, level=None) -> list[str]
    # tags
    def set_tags(self, logical_path, tags: list[str]) -> None
    def get_tags(self, logical_path) -> list[str]
    def files_by_tag(self, tag: str) -> list[dict]
    def all_tags(self) -> list[dict]
    # log
    def log_access(self, *, source, role, tool, target_path=None, outcome, code=None, details=None, session=None) -> None
    def access_log(self, *, limit=200, offset=0, source=None, outcome=None) -> list[dict]
    def access_log_count(self) -> int
    def export_access_log_csv(self, dest: Path) -> int
    # kv
    def kv_get(self, key, default=None) -> str | None
    def kv_set(self, key, value: str) -> None
```
Path handling: logical paths use `""` or `"/"` for the root? **Use `"/"` for the root** and
`"a/b"` for entries (no leading slash). `list_dir("/")` = top level. Normalize every argument.

## 7. `vault/core/vaultfs.py` — blob storage

```python
class VaultFS:
    def __init__(self, home: Path, index: Index, master_key: bytearray | None,
                 *, plain_threshold: int): ...
    def blob_path(self, blob_id: str) -> Path     # files/<blob_id[:2]>/<blob_id>.enc
    def read_bytes(self, row: dict) -> bytes                    # decrypts (uses master_key)
    def write_blob(self, data: bytes, *, sensitivity: str) -> tuple[str, int, bool]  # blob_id, size, encrypted
    def delete_blob(self, blob_id: str) -> None
    def gc_orphans(self) -> int                                  # blobs not referenced by any row
    def verify_blob(self, row: dict) -> bool                     # decrypt-test (used by a CLI)
```
- `blob_id = uuid4().hex`; sharded subdirectory; directory created on demand.
- A file whose size is **strictly greater** than `plain_threshold` is written plain
  (`encrypted=0` in the DB, header flag set).
- Replacing content writes a new blob and deletes the old one only after the DB row is updated.

## 8. `vault/core/store.py` — the encrypted content store (`secure.store` in the vault home)

A single encrypted blob whose plaintext is a small SQLite DB. Lifecycle: at unlock, decrypt it
into `runtime_dir()/store.dec` (mode 0600) and open it; on every mutation call `flush()`
(re-encrypt the file back into `secure.store`); on lock, flush and delete `store.dec`.

Plaintext-side schema:

```sql
CREATE VIRTUAL TABLE fts_content USING fts5(
  body, file_id UNINDEXED, tokenize="unicode61 remove_diacritics 2");
CREATE TABLE content_meta(file_id INTEGER PRIMARY KEY, sha256 TEXT, indexed_at INTEGER);
CREATE TABLE folder_notes(folder_path TEXT PRIMARY KEY, note_text TEXT NOT NULL, updated_at INTEGER);
CREATE TABLE vectors(file_id INTEGER PRIMARY KEY, model TEXT NOT NULL, dim INTEGER NOT NULL, vec BLOB NOT NULL);
```

```python
class SecureStore:
    @classmethod def create_new(cls, home: Path, master_key, *, sensitivity="normal") -> "SecureStore"
    @classmethod def open(cls, home: Path, master_key, runtime_dir: Path) -> "SecureStore"
    def flush(self) -> None
    def close(self) -> None            # flush + remove the decrypted file
    # content index (normal files only; caller guarantees the level)
    def index_text(self, file_id: int, text: str) -> None       # replaces the previous row
    def remove_file(self, file_id: int) -> None
    def search_text(self, query: str, *, limit=50) -> list[tuple[int, float]]   # (file_id, bm25 score)
    # folder notes
    def set_folder_note(self, folder_path: str, text: str) -> None
    def get_folder_note(self, folder_path: str) -> str | None
    def all_folder_notes(self) -> list[dict]
    # vectors
    def set_vector(self, file_id: int, model: str, vec: bytes) -> None
    def get_vectors(self, model: str) -> list[tuple[int, bytes]]
    def clear_vectors(self) -> int
    def stats(self) -> dict            # {"fts_rows": n, "notes": n, "vectors": n, "bytes": n}
```
Text stored in FTS is `normalize_fa(text)` of the file body; queries are normalized the same way.

## 9. `vault/core/security.py` — the policy boundary (single source of truth)

```python
LEVELS = ("normal", "secret", "secretfile")
LEVEL_RANK = {"normal": 0, "secret": 1, "secretfile": 2}
SOURCE_UI = "ui"; SOURCE_MCP = "mcp"; SOURCE_IMPORTER = "importer"

def rank(level: str) -> int
def is_higher_or_equal(a: str, b: str) -> bool

class Policy:
    """Encodes docs/DESIGN.md §4 exactly. Pure functions, no I/O — fully unit-tested."""
    @staticmethod def can_see_name(level: str, source: str) -> bool
    @staticmethod def can_read_content(level: str, source: str) -> bool        # ui: yes for normal+secret? -> see table
    @staticmethod def can_search_content(level: str, source: str) -> bool
    @staticmethod def can_request_open_secret(level: str, source: str) -> bool
    @staticmethod def can_raise(from_level: str, to_level: str, source: str) -> bool
    @staticmethod def can_lower(from_level: str, to_level: str, source: str) -> bool
    @staticmethod def ui_requires_confirmation(level: str) -> bool
    @staticmethod def ui_uses_native_viewer(level: str) -> bool
```

The matrix that must hold (design §4 + §7.3):

| level | see name (any source) | MCP read content | UI read content | content search | MCP request-open | UI viewer |
|---|---|---|---|---|---|---|
| `normal` | yes | yes | yes (no confirm) | yes | yes | web preview |
| `secret` | yes (+label) | **no** | yes, **after a confirmation dialog + tray notification** | no | **no** | native viewer (via UI confirm) |
| `secretfile` | yes (+label) | **no** | **native plain-text viewer only**, confirmation required | no | **yes** (`request_open_secret` → the UI window opens; the agent never receives content) | native viewer |

Also:
- `can_raise`: MCP and UI may raise (`normal→secret`, `normal→secretfile`, `secret→secretfile`).
  Any other combination from MCP (same level or lower) is `False` → the caller raises
  `DowngradeForbidden`.
- `can_lower`: **only** `SOURCE_UI`, and only to a *different* level (same level → `False`,
  it is a no-op). `importer` may set any level at creation time (it is UI-initiated) but must
  not lower an existing file (the importer never touches existing files).

## 10. `vault/core/search.py`

```python
class SearchKind(StrEnum): FILENAME = "filename"; TEXT = "text"; SEMANTIC = "semantic"

def search_filenames(session, query: str, *, limit=50, include_secret=True) -> list[dict]
def search_text(session, query: str, *, limit=50) -> list[dict]
def search_semantic(session, query: str, *, limit=50) -> list[dict]
```
- All three are **independent**; no result mixing, no re-ranking across kinds (design §6).
- Filename search = SQL `LIKE` over `normalize_fa(logical_path)` with `%q%` (plus a token-wise
  fallback: split the query on spaces and require every token to appear). It searches the
  **whole path**, and it does include `secret`/`secretfile` rows (names only).
- Text search requires an unlocked session (`VaultLocked` otherwise); FTS5 BM25 ordering;
  results carry `logical_path`, `snippet` (≤ 240 chars around the first match, computed in
  Python from the file body), and `score`. Only rows whose level is `normal` are indexed, so
  the check is naturally enforced — but re-check the level of each hit against `Policy` anyway
  and drop anything else (defence in depth).
- Semantic search: `ProviderUnavailable` when the provider is not installed/disabled; uses
  `semantics.py` and returns cosine similarity ≥ 0.25 ordered desc.
- Result dicts: `{"logical_path", "is_dir", "sensitivity", "size", "mtime", "match", "snippet"?, "score"?}`.

## 11. `vault/core/semantics.py` (opt-in, local only)

```python
class EmbeddingProvider(Protocol):
    name: str; dim: int; model: str
    def embed(self, texts: list[str]) -> list[list[float]]: ...

class LocalProvider:      # sentence-transformers; guarded import
    def __init__(self, model: str): ...     # ImportError -> ProviderUnavailable("install requirements-semantic.txt")
class StubProvider:       # deterministic, dependency-free, used by tests
    name = "stub"; dim = 64; model = "stub"
    def embed(self, texts): ...             # hashing bag-of-words → unit vector; must be deterministic
def get_provider(settings: dict) -> EmbeddingProvider      # raises ProviderUnavailable
def is_available(settings: dict) -> tuple[bool, str]       # (ok, reason)
def index_all(session, *, force=False, progress=None) -> dict   # {"indexed": n, "skipped": n}
def search(session, query, *, limit=50) -> list[dict]
```
Nothing is ever sent over the network by this module. Vectors live in the encrypted store.
`session.set_semantic_provider(provider)` allows injecting the stub in tests.

## 12. `vault/core/session.py` — the façade everything else uses

```python
class VaultSession:
    """Owns the vault state: meta, index, vaultfs, secure store, master key, lock state."""
    def __init__(self, home: Path, *, runtime_dir: Path | None = None, plain_threshold: int | None = None)
    # lifecycle
    @staticmethod def is_initialised(home: Path) -> bool
    @staticmethod def create(home: Path, password: str, *, settings: dict | None = None) -> "VaultSession"
    def unlock(self, password: str) -> None                 # wrong password -> Unauthorized("bad_password")
    def lock(self) -> None                                  # flush + wipe key + close store/index
    @property def is_locked(self) -> bool
    @property def home(self) -> Path
    def flush(self) -> None
    def close(self) -> None                                 # lock + release files
    def touch(self, *, source: str = "ui") -> None           # last-activity bookkeeping (auto-lock uses SOURCE_UI only)
    def auto_lock_due(self) -> bool
    def status(self) -> dict    # {"locked", "home", "files", "folders", "by_level", "semantic": {...}, "auto_lock_seconds", "store": {...}}
    # files (P1 surface; every method enforces Policy with the given source+role)
    def list_folder(self, path: str, *, source="ui") -> dict
    def read_file(self, path: str, *, source="ui", session=None) -> bytes
    def read_text(self, path: str, *, source="ui", encoding="utf-8") -> str
    def read_lines(self, path: str, start: int, count: int, *, source="ui") -> str
    def write_file(self, path: str, data: bytes, *, source="ui", create_parents=True, sensitivity=None) -> dict
    def write_lines(self, path: str, text: str, *, mode="append", at_line=None, source="ui") -> dict
    def mkdir(self, path: str, *, source="ui") -> dict
    def move(self, src: str, dst: str, *, source="ui") -> dict
    def copy(self, src: str, dst: str, *, source="ui") -> dict
    def delete(self, path: str, *, source="ui", recursive=False) -> dict
    def set_sensitivity(self, path: str, level: str, *, source="ui") -> dict
    def set_tags(self, path: str, tags: list[str], *, source="ui") -> dict
    def folder_note(self, path: str, *, source="ui") -> str | None
    def set_folder_note(self, path: str, text: str, *, source="ui") -> None
    # search
    def search_filenames(self, query, *, limit=50, source="ui") -> list[dict]
    def search_text(self, query, *, limit=50, source="ui") -> list[dict]
    def search_semantic(self, query, *, limit=50, source="ui") -> list[dict]
    # secrets / UI handoff (used by the daemon socket layer)
    def request_open_secret(self, path: str, *, source="mcp", session=None) -> dict
    def resolve_open_secret(self, request_id: str, *, approved: bool) -> dict   # called by the UI
    def pending_requests(self) -> list[dict]
    # log
    def access_log(self, **kw) -> list[dict]
```
Rules:
- Every method that touches content calls `Policy` first with the **role-derived source**
  (`ui` in-process; `mcp` from the socket token). A refusal logs `deny` + raises
  `PermissionDenied` (MCP/API layers convert to a response; the log entry is written either way).
- `write_file` on a `secret`/`secretfile` path from source `mcp` is **allowed only if the file
  already exists** (agents may maintain but not create secrets). Creating a new file whose
  `sensitivity` argument is not `normal` from MCP → `PermissionDenied`. Documented.
- `read_text`/`read_lines` on a `secretfile` never returns content to MCP.
- Content index updates: after any write to a `normal` file, re-index its text in the store
  (`index_text`) and store `sha256`; when a file becomes `secret`+, remove its rows from FTS
  and its vectors; when it is lowered back to `normal` (UI only), re-index.
- `request_open_secret` (source `mcp`): only for level `secretfile`; appends a pending request
  (uuid) and emits a Qt signal/notification via a callback registered by the UI
  (`session.on_secret_request = callable(request: dict)`); returns
  `{"request_id", "status": "pending"|"shown"|"denied"}`. The agent never gets the content.
- `auto_lock_due()` compares wall clock with the last `touch(source="ui")`; the daemon polls it
  (a Qt timer in the GUI, a thread in the headless daemon).
