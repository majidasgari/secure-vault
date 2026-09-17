# SPEC 04 — Importers (Joplin markdown mirror) and the CLIs

Module: `vault/importers/{__init__,base,joplin_mirror}.py`, CLI `tools/import_joplin.py`.

## 1. Base contract (`base.py`)

```python
@dataclass
class ImportReport:
    source: str
    started: int; finished: int
    notes_created: int; notes_updated: int; notes_skipped: int
    folders_created: int
    assets_imported: int; assets_skipped: int
    tags_applied: int
    errors: list[dict]          # {"path", "error", "code"}
    extra: dict                 # importer-specific counters
    def to_dict(self) -> dict                 # JSON-serialisable
    def to_markdown(self) -> str              # the report written to docs/reports/

class Importer(Protocol):
    name: str
    def run(self, session: VaultSession, *, dry_run: bool = False,
            progress: Callable[[str, int, int], None] | None = None) -> ImportReport: ...
```
`dry_run` walks everything and counts, writing **nothing** (the tests assert the vault is
byte-identical afterwards). `progress(label, done, total)` is called at most every 25 items.

## 2. Joplin mirror importer (`joplin_mirror.py`)

```python
class JoplinMirrorImporter:
    def __init__(self, mirror_root: Path, *, mark_secret_globs: list[str] = (),
                 default_level: str = "normal", include_stray_md: bool = True,
                 skip_names: tuple[str, ...] = DEFAULT_SKIP, import_assets: bool = True): ...
```

### 2.1 Source facts (verified on the real mirror — do not re-derive these)

`/data/Cloud/Documents/Notes/joplin-mirror` (read-only input):
* `_meta/index.json` — authoritative manifest. Keys and shapes:
  * `counts`: `{"notes": 876, "notebooks": 110, "tags": 22, "assets": 166, "missing_resource_binaries": 0, "unresolved_refs": 6}`
  * `notebooks`: `[{"id","name","path","parent"}]` — `path` is the notebook path *including
    weird leading characters* (`# برنامه‌ریزی`, `$پر استفاده`, `@چرک‌نویس`, `Welcome!`, …).
  * `notes`: `[{"id","title","path","notebook","tags":[…],"updated","created","source_url","is_todo"}]`
    — `path` is the mirror-relative markdown path (`کاری/آرشیو/…/note.md`), `tags` is a list of
    tag **names**, `updated`/`created` are ISO-8601 UTC strings.
  * `assets`: `{ "<resource_id>": "<filename inside assets/>" }` (166 entries).
  * `unresolved_refs`: `[{"note": "<note id>", "resource": "<resource id>"}]` — 6 refs whose
    binaries are absent; the importer must **not** fail on these (count them in
    `report.extra["unresolved_refs"]` and leave the original link text untouched).
* Note files carry a YAML-ish frontmatter block (`---` … `---`) with `id`, `parent_id`,
  `title`, `type_`, `created_time`, `updated_time`, `tags: [...]`, `source_url`, `is_todo`, …
  The body follows. `_index.md` files (111 of them) are **generated** by the mirror — never import.
* Mirror tooling that must be skipped: `_index.md`, `_meta/`, `_skills/`, `__pycache__/`,
  `README.md`, `browser.py`, `convert_jex.py`, `joplin_mcp.py`, `open-joplin.bat`,
  `open-joplin.sh` (make this the default `DEFAULT_SKIP` list; `--no-skip` disables it).
* `assets/` holds the resource binaries (133 png, 27 jpg, 2 svg, 4 md) — the 4 `.md` files in
  `assets/` must be treated as **assets** (they are referenced resources), not as notes, unless
  `include_stray_md` is on *and* they are absent from the manifest (they are present as assets,
  so they stay assets).

### 2.2 Mapping rules

1. **Folders**: every notebook in `notebooks[]` → a vault folder at
   `sanitize(notebook["path"])`; create parents first (sort by path depth). The root is `/`.
2. **Notes**: logical path = `sanitize(note["path"])` (keeps the notebook prefix, so structure
   is identical to the mirror). Body = the note file's content **without** the frontmatter block
   (the frontmatter is not duplicated into the body; the vault keeps Joplin's metadata in the
   importer's kv records instead). Title comes from the path; the importer must **not** rename
   files to `title.md` — the mirror path is the stable identity.
3. **sanitize(path)**: `normalize_logical_path` + replace `\ : * ? " < > |` (and any control
   char) with `_`, collapse `//`, strip trailing dots/spaces per path segment (Windows safety),
   keep `#`, `$`, `@`, Persian text and emoji as-is. Result must satisfy the core path rules.
4. **Timestamps**: `mtime` from `updated`, `created` from `created` (ISO-8601 → epoch ms,
   UTC-safe; unparseable → `now_ms()` and count in `report.extra["bad_timestamps"]`).
5. **Tags**: `note["tags"]` (names) → `session.set_tags(path, tags)`; skip empty. Names are
   stored verbatim (Unicode, Persian). `is_todo` → add the tag `todo`; if the body has a
   `- [ ]`/`- [x]` first line keep it as-is.
6. **Assets**: for every referenced resource id in the note bodies (`:/<32-hex>`) that exists in
   `index.assets` → import the binary as `<assets_folder>/<filename>` where `assets_folder`
   defaults to `attachments`; then rewrite `:/<id>` to the relative logical path of the
   imported file (i.e. `attachments/<filename>`; use a `/attachments/...` absolute-vault link
   when the note lives in a different folder, since markdown links resolve relatively —
   use `../../attachments/<file>` style only when `--relative-links` is given, default is the
   vault-absolute form `vault:/attachments/<file>`… **decision**: rewrite to
   `![…](vault:/attachments/<filename>)` for images and leave other forms as
   `vault:/attachments/<filename>`; document the `vault:` scheme in `docs/IMPORT_JOPLIN.md` and
   make the UI/editor resolve it). Binary assets are imported **plain** if larger than the plain
   threshold (they will be), otherwise encrypted like any file. Level = the note's level.
   Record `resource_id → logical path` in kv (`joplin:asset:<id>`).
7. **Sensitivity**: `default_level` (default `normal`) applies to notes and assets; any note
   whose logical path matches one of `--mark-secret GLOB` (fnmatch, case-insensitive, matched
   against the logical path **and** the title) is imported as `secret`. Globs are applied at
   creation only; an existing file's level is never changed (the importer must not lower levels).
8. **Idempotency**: kv keys `joplin:note:<note id>` → JSON `{"path", "updated"}` and
   `joplin:asset:<resource id>` → `{"path", "size", "sha256"}`.
   * note exists in kv and `updated` unchanged and the file exists → **skip** (`notes_skipped`);
   * `updated` changed → overwrite the content (`notes_updated`), keep the level and tags
     (tags are re-applied from the manifest, level untouched);
   * not in kv → create (`notes_created`); if the logical path already exists but is not tracked
     by the importer → **do not overwrite**: pick `<path> (imported 2).md`, count it in
     `report.extra["renamed_conflicts"]`.
   * a note removed from the mirror is **never** deleted from the vault (documented).
9. **Stray markdown** (`include_stray_md=True`, default): any `*.md` under the mirror that is
   neither a note of the manifest nor a skipped name is imported as a normal note into the
   folder it lives in, tracked as `joplin:stray:<relpath>` with a sha256 (this is how the stray
   `کاری/ایده‌ها/secure-vault/DESIGN.md` gets in). Report them in
   `report.extra["stray_imported"]` (list of paths).
10. **Never write to the mirror**: open files read-only; assert `mirror_root` is not inside the
    vault home and refuse to run otherwise (`BadRequest`).

### 2.3 Output
* Console: a one-line progress per 100 items + a final table (created/updated/skipped/errors).
* `--report PATH` (default `docs/reports/joplin-import-<UTC timestamp>.md` via `report.to_markdown()`)
  — written **outside** the vault home (docs is in the repo). The report contains counts, the
  list of errors, the stray list, and the unresolved refs.
* Exit code 0 if `errors == []`, 1 if there were errors (`--allow-errors` overrides).

### 2.4 CLI

```
python tools/import_joplin.py --home <vault home> --unlock-file <0600 file with the password>
       [--mirror PATH] [--mark-secret GLOB]... [--default-level normal|secret] [--dry-run]
       [--no-assets] [--no-stray] [--report PATH] [--json] [--debug]
```
Reads the password from a `0600` file (never argv, never stdin echoing), unlocks, imports,
prints the report (and `--json` prints `report.to_dict()`). Refuses if the vault is locked
(`VAULT_LOCKED`).

## 3. KeePass — explicit non-goal (documented in `docs/IMPORT_JOPLIN.md` and README)

There is **no** kdbx importer and there will not be one (user decision in the original design,
`docs/DESIGN.md` §14). Passwords belong in `secretfile` files inside the vault: one file per
credential or one markdown note per service, imported by hand or written by the user. The
README documents the recommended shape:

```markdown
# خدمت: <name>
username: <…>
password: <…>
url: <…>
notes: <…>
```
and recommends the folder `secrets/` with `secretfile` level on each entry. The importer has a
`--seed-example` flag that creates `secrets/EXAMPLE.md` (a normal file) explaining the shape.
