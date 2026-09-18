# پرامپت ۲ برای opencode — کشِ بردارها (content-addressed embedding cache)

تو داخل ریپوی **Secure Vault** (`/data/Codes/secure-vault`) کار می‌کنی. یک فاز کامل است. مرجعِ کامل
طرح: `docs/SEMANTIC-VECTOR-CACHE.md` — همان را دقیقاً پیاده کن. خلاصهٔ الزامات:

## چرا

ایندکس معنایی دادهٔ «مشتق» است، ولی امروز هر بازسازی همهٔ چانک‌ها را از صفر امبد می‌کند
(`semantics.index_all` → `provider.embed`)، و `SemanticStore.ensure_layout` در ناهمخوانی
`(model, dim, chunking)` کل ایندکس را پاک می‌کند. اندازهٔ واقعی: `BAAI/bge-m3`، ~۲۲٬۰۰۰ چانک، ایندکس
~۱۰۶MB، هر پاسِ کامل ساعت‌ها CPU. با یک کش محتوایی، پاک‌شدن ایندکس و بازسازی‌اش می‌شود چند ثانیه lookup.

## طرح

**کلید per-chunk:**
```
content = sha256(normalized_chunk_text)
key     = HMAC_SHA256(cache_salt, f"{model}|{dim}|{normalizer_version}|{content}")
```
- `cache_salt`: ۳۲ بایت تصادفی که بار اول ساخته و در `meta` خودِ کش ذخیره می‌شود (این salt برای این
  است که فایلِ کشِ رمزنگاری‌نشده هیچ چیزی دربارهٔ «چه پاراگراف‌هایی در والت هست» لو ندهد؛ هشِ خالی کافی نیست).
- `normalizer_version`: ثابت ماژولی، هر وقت `chunk_text`/`normalize_fa` خروجی‌شان برای ورودی یکسان عوض شد، +۱.
- **حالت چانکینگ داخل کلید نیست** (کلید = متن). پس عوض‌کردن paragraph↔sentence↔document هیچ بردار
  قابل‌استفاده‌ای را بی‌اعتبار نمی‌کند.

**ذخیره:** یک SQLite در
`<user_data_dir()>/semantic/cache/<model-slug>__<dim>.db` (مثلاً `BAAI__bge-m3__1024.db`):

```sql
CREATE TABLE meta   (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE vectors(key BLOB PRIMARY KEY, vec BLOB NOT NULL, dim INTEGER NOT NULL,
                     created_at INTEGER NOT NULL, last_used_at INTEGER NOT NULL,
                     hits INTEGER NOT NULL DEFAULT 0);
CREATE INDEX vectors_lru ON vectors(last_used_at);
```
`journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`. نوشتن‌ها تراکنشی
(`INSERT ... ON CONFLICT(key) DO UPDATE ...`). هیچ‌وقت رمزنگاری/سینک/بکاپ نمی‌شود (قابل بازسازی است) و
باید در `docs/SYNC.md` کنار بقیهٔ مسیرهای «هرگز سینک نمی‌شود» فهرست شود.

**ماژول تازه:** `src/vault/core/vector_cache.py`

```python
class VectorCache:
    def __init__(self, path=None, *, model: str, dim: int, normalizer_version: int = NORMALIZER_VERSION): ...
    @classmethod
    def for_model(cls, model: str, dim: int) -> "VectorCache": ...
    def key(self, text: str) -> bytes: ...
    def lookup(self, texts: list[str]) -> dict[int, list[float]]: ...   # اندیس در لیست ورودی -> بردار
    def store(self, texts: list[str], vectors: list[list[float]]) -> int: ...
    def stats(self) -> dict: ...   # entries, bytes, hits, misses, hit_rate, path
    def prune(self, max_bytes: int | None = None, idle_days: int | None = None) -> int: ...
    def clear(self) -> int: ...
```
- `lookup` باید دسته‌ای باشد: کلیدها را در گروه‌های ≤۹۰۰ پارامترِ bind بفرست (سقف SQLite).
- هر خطای SQLite/خرابی = **cache miss** با یک WARNING یک‌باره؛ هرگز ایندکس را fail نکند.
- سقف پیش‌فرض **۵۱۲MB** (`settings.semantic.cache_max_mb`)، هرس LRU هنگام باز شدن و بعد از هر
  ~۲۰۰۰ درج؛ ردیف‌های استفاده‌شده در همان اجرا هرس نشوند.
- بردارها با همان `semantics._pack` (float32 little-endian) ذخیره شوند تا خروجی بایت‌به‌بایت مثل امروز بماند.

**اتصال:** در `semantics.index_all`:
```python
cache = VectorCache.for_model(provider.model, provider.dim)
hits  = cache.lookup([t for _, _, t in pending])
misses = [(pos, row) for pos, row in enumerate(pending) if pos not in hits]
vecs   = provider.embed([t for _, _, t in misses]) if misses else []
cache.store([t for _, _, t in misses], vecs)
# سپس ساخت ردیف‌ها از hits + بردارهای تازه، دقیقاً مثل کد فعلی
```
همچنین در `vault.semantic_reindex` و در مسیر auto-index (که در پرامپت ۱ صف‌دار می‌شود) استفاده شود.

## UX / تنظیمات / i18n

- Settings → «جست‌وجوی معنایی»: یک خط فقط‌خواندنی «کش بردارها: N بردار · X MB · نرخ اصابت Y٪» و
  دکمهٔ «خالی کردن کش» با تأیید.
- کلیدهای i18n به **هر دو** `i18n/fa.json` و `i18n/en.json` و با مجموعه‌کلید یکسان اضافه شوند.
- `semantic_status` (و `vault.status`) علاوه بر `cache:{...}`، فیلد `last_reset:{at,reason,prev_*}`
  را هم برگرداند (اگر پرامپت ۱ را هم اجرا کرده‌ای).

## تست‌ها — `tests/test_vector_cache.py`

1. **بدون امبد تکراری:** با یک provider شمارنده (decorator روی استاب موجود)، پاس دوم روی همان والتِ
   اسکرچ صفر متن به `embed()` بفرستد و نتیجهٔ جست‌وجو هم عوض نشود (تست invariance).
2. **جدایی مدل‌ها:** مدل/بُعد دوم فایل خودش را بسازد و هیچ بردار بیگانه‌ای برنگرداند.
3. **تغییر چانکینگ ارزان است:** paragraph → sentence → paragraph هیچ چانکی با متن یکسان را دوباره امبد نکند.
4. **خرابی = miss:** کوتاه‌کردن یک `vec` یا حذف جدول، خطا ندهد.
5. **هرس:** با `cache_max_mb` کوچک، قدیمی‌ترین‌ها اول بروند و آمار سازگار بماند.
6. **تغییر salt:** همه کلیدها miss شوند (هیچ اصابت غلطی نباشد).
7. `./.venv/bin/python tests/run_tests.py` سبز.

## قیدهای مهم

- **به والت واقعی کاربر دست نزن:** `/data/Cloud/Documents/SecureVault` و
  `~/.local/share/secure-vault/semantic/*.db` را نه بخوان نه پاک کن نه اندازه‌گیری روی آن‌ها انجام بده.
  همهٔ تست‌ها/بنچمارک‌ها روی والتِ اسکرچ و مسیرهای temp باشند (`XDG_DATA_HOME` را در تست به temp ببر).
- فایل‌های یتیمِ قدیمی در `semantic/` را پاک نکن (کاربر خودش تصمیم می‌گیرد)؛ فقط مطمئن شو کدِ جدید
  بیرون از `semantic/cache/` فایل تازه نمی‌سازد.
- هیچ وابستگی تازه، هیچ شبکه، هیچ کامیتی. حداقل تغییر و بدون بازنویسی فایل‌های نامرتبط.
- در پایان بده: فایل‌های تغییریافته، خروجی تست‌ها، و یک اندازه‌گیری واقعی روی والتِ اسکرچ
  (بار اول = چند امبد، بار دوم = صفر امبد، زمان هر دو).
