# SEMANTIC-VECTOR-CACHE.md — content-addressed embedding cache (spec for opencode)

Self-contained implementation contract. Read with `SPEC/01-core.md §11` (semantic index) and
`docs/SYNC.md` (what is never synced). Existing code: `src/vault/core/semantics.py`,
`src/vault/core/chunking.py`, `src/vault/core/semantic_store.py`, `src/vault/config.py`.

## 1. Why

The semantic index is *derived* data, but today every rebuild re-embeds every chunk from scratch:
`semantics.index_all` calls `provider.embed(pending_texts)` for whatever it decides to (re)index,
and `SemanticStore.ensure_layout()` **wipes the whole index** whenever `(model, dim, chunking)`
differs from the stored meta or the `vec_chunks` table is missing. Measured on the real vault: the
`BAAI/bge-m3` index is ~22 000 chunks / 106 MB and a full pass costs hours of CPU, and the wipe has
happened repeatedly in a single day (auto-index-on-write calls `index_all` → `ensure_layout` on
every write). Re-embedding is a pure waste when the text has not changed.

Goal: an **embedding cache keyed by the chunk's content digest, per model**, so the same paragraph
is never embedded twice on this machine — for any model, any chunking mode, any wipe.

## 2. Design

**Key.** For every chunk text `t` (the string produced by `chunk_text()`, after `normalize_fa`):

```
content = sha256(t.encode("utf-8")).hexdigest()
key     = HMAC_SHA256(cache_salt, f"{model}|{dim}|{normalizer_version}|{content}")
```

* `cache_salt` is 32 random bytes generated on first use and stored in the cache's own `meta`
  table. It is **not** the vault key. (Plain MD5 was the original idea; the HMAC matters because the
  cache lives unencrypted in the user's home — with a bare digest anyone holding the file could test
  "does this exact paragraph exist in his vault?" for any paragraph they can guess.)
* `model`, `dim` → from the provider. `normalizer_version` is a module constant bumped whenever
  `normalize_fa` / `chunk_text` change their output for the same input (start at `1`).
* Chunking mode is deliberately **not** in the key: the key is the *text*. Switching
  paragraph↔sentence↔document re-uses every vector whose chunk text is unchanged, and a wipe costs
  lookups only.

**Storage.** One SQLite file per model, unencrypted, under the user data dir:

```
<user_data_dir()>/semantic/cache/<model-slug>__<dim>.db        # e.g. BAAI__bge-m3__1024.db
```

```sql
CREATE TABLE meta   (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE vectors(
  key          BLOB PRIMARY KEY,   -- 32-byte HMAC
  vec          BLOB NOT NULL,      -- little-endian float32 (same packing as semantics._pack)
  dim          INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,   -- epoch ms
  last_used_at INTEGER NOT NULL,
  hits         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX vectors_lru ON vectors(last_used_at);
```

* `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;` — the app and any
  agent tool may open it concurrently; every write is one transaction (`INSERT ... ON CONFLICT(key)
  DO UPDATE SET vec=excluded.vec, last_used_at=excluded.last_used_at, hits=hits+1`).
* Never encrypt, never sync, never back up: it is rebuildable, and `docs/SYNC.md` must list it with
  the other "never synced" paths.
* Default cap **512 MB**, `prune` on open and after every N=2000 inserts: delete least-recently-used
  rows until under the cap. Never prune rows used in the current run.

**Module.** New file `src/vault/core/vector_cache.py`:

```python
class VectorCache:
    def __init__(self, path: Path | None = None, *, model: str, dim: int,
                 normalizer_version: int = NORMALIZER_VERSION) -> None: ...
    @classmethod
    def for_model(cls, model: str, dim: int) -> "VectorCache": ...   # resolves the path
    def key(self, text: str) -> bytes: ...                            # hmac_digest
    def lookup(self, texts: list[str]) -> dict[int, list[float]]: ... # index-in-list -> vector
    def store(self, texts: list[str], vectors: list[list[float]]) -> int: ...
    def stats(self) -> dict[str, Any]: ...   # entries, bytes, hits, misses, hit_rate, path
    def prune(self, max_bytes: int | None = None, idle_days: int | None = None) -> int: ...
    def clear(self) -> int: ...
```

* `lookup` must batch the SQL: chunk the key list into groups of ≤ 900 bound parameters (SQLite
  limit) and union the results; return only hits, keyed by the caller's list index.
* Any SQLite/corruption error is a **cache miss**, logged once at WARNING, never a failed index
  (`ProviderUnavailable` is the only error allowed to escape).

**Integration (`semantics.index_all`).**

```python
cache = VectorCache.for_model(provider.model, provider.dim)
...
pending = [...]                      # (file_id, ord, normalized_text) as today
hits   = cache.lookup([t for _, _, t in pending])
misses = [(pos, row) for pos, row in enumerate(pending) if pos not in hits]
vectors_from_model = provider.embed([t for _, _, t in misses]) if misses else []
cache.store([t for _, _, t in misses], vectors_from_model)       # one transaction
# then assemble rows exactly as today, from hits + model vectors
```

`store()` is called with the *misses only*; the returned rows must be byte-identical to today's
(`_pack`ed float32) so that search results do not change. Also wire the cache into
`vault.semantic_reindex` and into the per-write auto-index (which will, after the separate
queue/debounce fix, mostly hit the cache).

**Fix in the same PR (both are required for this to be worth anything):**

1. `SemanticStore.ensure_layout`: never wipe implicitly. On a `(model, dim, chunking)` mismatch or a
   missing `vec_chunks`: rename the old blob to `<hash>.db.bak`, record
   `last_reset = {at, reason, prev_model, prev_dim, prev_chunking}` in the store meta, and **refuse**
   the wipe when the call came from the auto-index path (`index_all(prefix=...)`, `force=True`) —
   skip that file and log. Only an explicit user rebuild (Settings → «بازسازی ایندکس جست‌وجو») or
   `vault.semantic_reindex(force=True)` may reset, and it must say so in a progress dialog.
2. `_auto_index_semantics` must not run inline on the write path: enqueue the path in a small
   background worker (single thread, 2–5 s debounce, coalesce duplicates, bounded queue) so a bulk
   write (hundreds of notes) cannot saturate the app or starve the socket server.
3. `semantic_status` gains: `cache: {entries, bytes, hits, misses, hit_rate, path}` and
   `last_reset: {at, reason, prev_model, prev_dim, prev_chunking}`.

## 3. UX / settings

* Settings → «جست‌وجوی معنایی» shows a read-only line: «کش بردارها: N بردار · X MB · نرخ اصابت Y٪»
  and a «خالی کردن کش» button (with a confirm dialog). No new config keys besides the cap (reuse
  `semantic` settings, e.g. `semantic.cache_max_mb`, default 512).
* i18n: add the keys to **both** `i18n/fa.json` and `i18n/en.json` with identical key sets.

## 4. Tests (`tests/test_vector_cache.py`, stdlib + the stub provider)

1. **No re-embedding:** index a scratch vault twice with a *counting* provider wrapper; the second
   pass must call `embed()` with 0 texts (and produce identical search results — invariance).
2. **Model isolation:** a second model/dim writes its own file and never returns foreign vectors.
3. **Chunking change is cheap:** indexing the same file with `sentence` after `paragraph`, then back,
   re-embeds nothing that shares a chunk text.
4. **Corruption is a miss:** truncating a `vec` blob (or dropping the table) never raises.
5. **Prune:** with a tiny `cache_max_mb`, the least-recently-used rows go first and stats stay
   consistent.
6. **Salt change:** a new `cache_salt` makes every key miss (and re-stores), never a wrong hit.
7. **Layout guard:** calling `ensure_layout` with a different model from the auto-index path does not
   wipe the live index (this is the regression test for today's incident).
8. `scripts/run_tests` equivalent: `./.venv/bin/python tests/run_tests.py` green.

## 5. Acceptance (measure on the real vault, report the numbers)

* Cold cache: a full `semantic_reindex` on the real vault ≈ today's cost (baseline: ~22 000 chunks).
* Warm cache: the same rebuild finishes in **under a minute** (lookups only) — measure and report.
* With the app open and four agent writers writing notes, the socket answers requests within ~1 s
  (today it accepts and immediately closes connections while embedding).
* Drop the stray `<hash>.db` files the old behaviour left in `~/.local/share/secure-vault/semantic/`
  (33 scratch DBs, ~10 MB) — the new layout must keep exactly one file per model in `semantic/` plus
  the files in `semantic/cache/`.
