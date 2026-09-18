# پرامپت ۱ برای opencode — توقفِ پاک‌شدنِ خاموش ایندکس + صف‌دار کردن auto-index

تو داخل ریپوی **Secure Vault** (`/data/Codes/secure-vault`) کار می‌کنی. این یک تسک دقیق و محدود است؛ فقط همین تغییرها را بده.

## زمینهٔ حادثه (شاهد واقعی، امروز)

کشور کاربر: والت واقعی (`/data/Cloud/Documents/SecureVault`) با ایندکس معنایی `BAAI/bge-m3`
(~۲۲٬۰۰۰ چانک، ایندکس رمزنگاری‌شده ~۱۰۶MB در `~/.local/share/secure-vault/semantic/`). کاربر چند صد
`note` روی فایل‌ها نوشت؛ اپ حدود ۴۵ دقیقه روی ۵۰۰–۸۴۰٪ CPU گیر کرد و سوکت محلی **اتصال را می‌پذیرفت و
بی‌درنگ می‌بست** (`VaultNotRunning: daemon closed the connection`) — یعنی وبUI، پل MCP و هر کلاینت از کار
افتاد. علت ریشه‌ای در کد روشن است:

1. `src/vault/core/semantic_store.py` → `SemanticStore.ensure_layout(model, dim, chunking)`:
   اگر `(model, dim, chunking)` با متای ذخیره‌شده فرق کند **یا** جدول `vec_chunks` پیدا نشود،
   کل ایندکس را `self.reset()` می‌کند: بی‌لاگ، بی‌بکاپ، بی‌راه برگشت. هر ناهمخوانی = ساعت‌ها امبدینگ از صفر.
2. `src/vault/core/semantics.py` → `index_all()` در خط اولش `store.ensure_layout(provider.model,
   provider.dim, mode)` را صدا می‌زند — **حتی وقتی `prefix` به یک فایل محدود است**.
3. `src/vault/core/session.py` → `_auto_index_semantics(logical)` که در مسیر `write_file` /
   `set_file_note` صدا زده می‌شود، `index_semantics(force=True, prefix=logical, refresh=False)` را
   **inline و در همان تردِ نوشتن** اجرا می‌کند. یعنی هر نوشتن می‌تواند (الف) کل ایندکس را پاک کند و
   (ب) تردِ سرور را برای دقایق با امبدینگ قفل کند.
4. `semantics.get_provider()` وقتی فیلد `semantic.model` نباشد، به `all-MiniLM-L6-v2` (بُعد ۳۸۴)
   برمی‌گردد؛ در حالی که ایندکس با `bge-m3` (بُعد ۱۰۲۴) ساخته شده → ناهمخوانی بُعد → پاک‌شدن خاموش.

## کاری که باید بکنی

**۱. پایان دادن به پاک‌شدنِ خاموش.**
- در `ensure_layout`: در ناهمخوانی، **هرگز** مستقیم `reset()` نکن. اول اسنپ‌شات بگیر: بلاب فعلی را به
  `<نام>.db.bak` تغییر نام بده، و در متای استور ثبت کن:
  `last_reset = {"at": ms, "reason": "...", "prev_model": ..., "prev_dim": ..., "prev_chunking": ...}`.
- `index_all` باید پارامتری مثل `allow_reset: bool = False` بگیرد. از مسیر auto-index/prefix دار
  (`force=True, prefix=...`) همیشه `allow_reset=False` باشد و در ناهمخوانی، آن فایل را **رد کند**
  (log یک بار در WARNING) — نه اینکه ایندکس را پاک کند.
- فقط بازسازی صریح کاربر (`vault.semantic_reindex` با `force=True` از UI یا Settings) اجازهٔ
  `allow_reset=True` دارد؛ و همان هم باید `reason` و `prev_*` را در payload پیشرفت برگرداند تا UI
  بتواند بگوید «چرا دوباره ساخته می‌شود».
- قبل از هر reset، مدل را واقعاً load کن؛ اگر بالا نیامد، reset نکن و خطای `ProviderUnavailable` بده.

**۲. حذف fallback خاموش مدل.**
- در `semantics.get_provider()` اگر `semantic.model` خالی/غایب بود، `ProviderUnavailable("model_not_set")`
  بده. هیچ پیش‌فرضی که بُعدش فرق دارد نگذار.

**۳. auto-index را از مسیر نوشتن بیرون بکش و صف‌دار کن.**
- یک worker تک‌تردِ پس‌زمینه (قابل توقف تمیز در lock/close) با **debounce ۲–۵ ثانیه**، ادغام
  مسیرهای تکراری (coalesce)، صف کراندار (پیشنهاد: ۵۰۰) و «آخرین برنده» برای یک مسیر تکراری.
- نوشتن باید **بلافاصله** برگردد؛ worker بعداً و جدا امبد می‌کند. خطاها فقط یک بار log شوند
  (best-effort مثل امروز: شکستِ ایندکس نباید نوشتن را fail کند).
- در پایان کار worker، `flush()`/`save` همان‌طور که الان در مسیر نوشتن انجام می‌شود رعایت شود تا
  استور رمزنگاری‌شده پایدار بماند (بدون قفل‌شدن طولانی روی ترد UI).

**۴. قابل‌مشاهده کردن وضعیت.**
- `vault.semantic_status` (و همان کلید در `vault.status`) این‌ها را برگرداند:
  `last_reset: {at, reason, prev_model, prev_dim, prev_chunking}` و
  `queue: {pending, debounce_ms, last_error}`.

## قیدها

- سیاست‌های موجود را نشکن: یک ردیف access-log برای هر فراخوان، `QUIET_METHODS` دست‌نخورده،
  retention در `core/retention.py` (هیچ DELETE روی access_log در لایهٔ داده نگذار).
- هیچ وابستگی تازه، هیچ شبکه، هیچ کامیتی نزن. فایل‌های نامرتبط را بازنویسی نکن.
- تست‌های خودت را در `tests/test_semantic_guard.py` بنویس (stdlib + استاب provider موجود):
  1. با مدل ناهمخوان از مسیر auto-index، ایندکس زنده **پاک نشود** (تعداد ردیف چانک‌ها حفظ شود)؛
  2. بازسازی صریح، reset بکند و `last_reset` را درست ثبت کند؛
  3. چند نوشتن پشت‌سرهم روی یک فایل → یک پاس ایندکس، و نوشتن بدون انتظار برگردد (صف را بعداً خالی کن)؛
  4. نبودِ `semantic.model` → `ProviderUnavailable` (نه fallback).
- در پایان `./.venv/bin/python tests/run_tests.py` باید سبز باشد. خلاصهٔ فایل‌های تغییریافته، خروجی
  تست‌ها و هر «انحراف از این پرامپت» را گزارش کن.
