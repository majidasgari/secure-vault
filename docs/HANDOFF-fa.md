# یادداشت تحویل گاوصندوق (فارسی)

این سند کوتاه و عملی است: چه چیزی ساخته شده، چطور اجرا شود، چطور به ایجنت‌ها دسترسی
داده شود، چطور از Joplin ایمپورت کنید، چه چیزهایی هنوز آزمایش نشده‌اند، و دستورهای
دقیق تست‌ها.

## چه چیزی پیاده‌سازی شده

* هسته‌ی رمزنگاری: AES-256-GCM، Argon2id (با فالبک PBKDF2)، HKDF برای هر فایل،
  قفل/بازکردن، سطوح حساسیت `normal` / `secret` / `secretfile`.
* ذخیره‌سازی: `meta.sqlite` (نام‌ها/سطح/برچسب/لاگ) + `secure.store` رمزنگاری‌شده
  (ایندکس FTS، یادداشت پوشه، بردارها) + بلاب‌های `files/`.
* رابط گرافیکی Qt (PySide6) با مرورگر، ویرایشگر markdown، نمایشگر بومی فایل رمز،
  جستجوی سه‌گانه، پنل لاگ، تنظیمات، tray و اعلان‌ها، دو زبانه fa/en با RTL.
* API محلی روی Unix socket با توکن نقش `mcp` + پل MCP روی stdio
  (`bin/secure-vault-mcp`) + دیمن بدون گرافیک (`python -m vault.daemon`).
* رابط وب مرورگری (`bin/secure-vault-web`، `python -m vault.web`) با احراز توکن،
  API روی `Service.dispatch(role="ui")`، جریان رویداد SSE و SPA آفلاین fa/en؛
  هم‌ترازی با مرورگر آینه: درخت تاشو با شمارش زیردرخت، تراشه‌های برچسب، جستجوی
  یک‌جعبه‌ای با قطعه‌ی متن، نمای خام، ویرایشگر با نوار قالب‌بندی، پیش‌نمایش مارک‌داون
  سمت مرورگر (چک‌لیست/جدول/کد LTR) و سرو تصاویر از `/api/blob`.
* پوستهٔ tray به‌عنوان رابط همیشه‌روشن (SPEC/09): رابط وب **خودکار و درون‌فرایندی** روی
  همان نشست بالا می‌آید، tray دروازهٔ رمز است (دیالوگ «نمایش و کپی»)، و همیشه
  «کدام فایل الان خوانده می‌شود» را نشان می‌دهد (فید فعالیت + tooltip + منو + SSE).
* ویرایشگر Qt با راست‌چین/چپ‌چین درست به‌ازای هر بلوک (`src/vault/ui/bidi.py`)،
  کنترل حالت خودکار/راست‌به‌چپ/چپ‌به‌راست (`Ctrl+Shift+D`) و دکمهٔ «ویرایش در مرورگر».
* ایمپورتر آینه‌ی Joplin (خواندن فقط‌خواندنی، idempotent، بازنویسی لینک‌ها به
  `vault:/attachments/...`).
* بسته‌بندی: `tools/bootstrap.sh`، لانچرها، نصب دسکتاپ، سازنده‌ی portable ویندوز،
  `pyproject.toml` و مستندات.
* سینک S3 اختیاری (بدون نیاز به بستهٔ اضافه — امضای SigV4 درون‌برنامه‌ای است؛
  `requirements-s3.txt` فقط برای بک‌اند اختیاری boto3): آینه‌سازی دوطرفه‌ی کل پوشه‌ی گاوصندوق با
  قفل فایل در سبد؛ اگر دستگاه دیگری قفل را داشته باشد، نشست **فقط‌خواندنی** می‌شود تا
  دکمه‌ی «گرفتن دسترسی نوشتن» را بزنید. دکمه‌ی «همگام‌سازی» هم در اپ و هم در رابط وب
  هست. بردارهای معنایی و کش جای‌گذاری بیرون گاوصندوق‌اند و هرگز سینک نمی‌شوند؛ تنظیمات
  مسیر داخلی برای کش بردار را رد می‌کند. جزئیات در `docs/SYNC.md`.

## اجرا

```bash
cd /data/Codes/secure-vault
tools/bootstrap.sh            # ساخت/به‌روزرسانی .venv، نصب وابستگی‌ها، فونت‌ها
./bin/secure-vault            # اجرای برنامه
```

در اجرای اول: پوشه‌ی گاوصندوق (پیش‌فرض `/data/Cloud/SecureVault`) و گذرواژه‌ی اصلی را
انتخاب کنید. **گذرواژه ذخیره نمی‌شود و بازیابی ندارد.** روی این ماشین که صفحه‌نمایش
واقعی در دسترس نیست، می‌توانید بدون گرافیک تست کنید:

```bash
QT_QPA_PLATFORM=offscreen ./bin/secure-vault --self-test
```

نصب آیکون و میان‌بر منوی KDE:

```bash
tools/install-desktop.sh
# حذف:
tools/uninstall-desktop.sh
```

## اجرا از مرورگر (رابط وب)

همان گاوصندوق از طریق مرورگر هم قابل استفاده است؛ فرایند وب مالک نشست است و
کلیدها هرگز از آن خارج نمی‌شوند:

```bash
./bin/secure-vault-web --home /path/to/vault --port 8788
# یا: PYTHONPATH=src ./.venv/bin/python -m vault.web --port 0
```

نشانی و یک **توکن دسترسی** یک‌بار روی stderr چاپ می‌شود. توکن را در صفحهٔ ورود
بچسبانید و سپس گذرواژهٔ اصلی را وارد کنید. هر درخواست `/api/*` باید توکن را در
هدر `X-Vault-Token` داشته باشد؛ کوکیِ لینک `/?token=…` به‌تنهایی مجاز نمی‌کند.
رابط فارسی/RTL، واکنش‌گرا تا موبایل و کاملاً آفلاین است. برای اتصال به شبکه باید
صریحاً `--allow-lan` بدهید. جزئیات در `docs/WEBUI.md`.

از این پس لازم نیست رابط وب را جدا اجرا کنید: با بالا آمدن برنامهٔ Qt، سرور وب
**در همان فرایند و روی همان نشست** خودکار بالا می‌آید (تنظیم `web.enabled`، پیش‌فرض
روشن). از منوی tray «باز کردن رابط وب» یا «کپی لینک رابط وب» استفاده کنید. اگر
درگاه/فایل توکن مال نمونهٔ دیگری باشد، این نمونه آن را قبضه نمی‌کند و tray به همان
نمونهٔ در حال اجرا اشاره می‌کند. برای دیدن/ویرایش در مرورگر، در ویرایشگر Qt دکمهٔ
«ویرایش در مرورگر» را بزنید.

## دسترسی ایجنت‌ها (Hermes MCP)

برنامه باید در حال اجرا و باز (unlocked) باشد. مسیر کامل پل را ثبت کنید:

```json
{
  "mcp_servers": {
    "secure-vault": {
      "command": "/data/Codes/secure-vault/bin/secure-vault-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

یا با CLI:

```bash
hermes config set mcp_servers.secure-vault.command "/data/Codes/secure-vault/bin/secure-vault-mcp"
hermes config set mcp_servers.secure-vault.args "[]"
```

اگر نسخه‌ی Hermes شما کلید `mcpServers` می‌خواهد، همان را به کار ببرید. برای عیب‌یابی،
`SECURE_VAULT_DEBUG=1` را در `env` بگذارید (خروجی فقط روی stderr می‌رود؛ stdout کانال
JSON-RPC است). ایجنت می‌تواند نام‌ها/ساختار را ببیند، فایل‌های `normal` را بخواند و
بنویسد، جستجو کند و سطح را **بالا** ببرد؛ اما محتوای `secret`/`secretfile` را هرگز
نمی‌بیند، نمی‌تواند سطح را پایین بیاورد، و `request_open_secret` فقط درخواست نمایش
به شماست (محتوا به ایجنت نمی‌رسد). جزئیات در `docs/MCP.md`.

## ایمپورت از Joplin

```bash
printf '%s' 'گذرواژه‌ی‌اصلی' > /tmp/sv.pw && chmod 600 /tmp/sv.pw
# اول dry-run روی یک گاوصندوق آزمایشی:
./.venv/bin/python tools/import_joplin.py \
    --home /tmp/scratch-vault --unlock-file /tmp/sv.pw --dry-run
# سپس ایمپورت واقعی:
./.venv/bin/python tools/import_joplin.py \
    --home /tmp/scratch-vault --unlock-file /tmp/sv.pw \
    --report docs/reports/joplin-real.md
```

آینه هرگز تغییر نمی‌کند، اجرای دوم بی‌اثر است، و لینک منابع به
`vault:/attachments/<file>` تبدیل می‌شود. KeePass پشتیبانی نمی‌شود؛ گذرواژه‌ها را در
فایل‌های `secretfile` نگه دارید (نمونه در `docs/IMPORT_JOPLIN.md`).

## چه چیزهایی هنوز آزمایش نشده‌اند

* **رابط گرافیکی روی صفحه‌ی واقعی شما**: فونت فارسی و RTL، آیکون در منو/taskbar، tray،
  اعلان‌ها، و پنجره‌ی درخواست فایل رمز — فقط به‌صورت offscreen تست شده‌اند.
* **بیلد portable ویندوز**: ساخته می‌شود ولی هرگز روی ویندوز واقعی اجرا نشده است
  (`docs/WINDOWS.md`).
* **جستجوی معنایی**: نیازمند نصب اختیاری `requirements-semantic.txt`
  (`sentence-transformers`) است؛ بدون آن، جستجوی معنایی `PROVIDER_UNAVAILABLE`
  برمی‌گرداند و بقیه‌ی برنامه سالم است.
* **ایمپورت به گاوصندوق واقعی خودتان** و سینک با پوشه‌ی ابری.
* **رابط وب روی مرورگر واقعی و موبایل**: فقط به‌صورت HTTP/headless تست شده؛
  چیدمان موبایل، RTL و فونت وزیرمتن را باید روی مرورگر واقعی ببینید.
* **tray و جهت‌دهی زندهٔ ویرایشگر روی صفحهٔ واقعی**: منوی «آخرین خوانده‌ها»، نشان 🔑 و
  رنگ‌آمیزی راست‌به‌چپ بلوک‌ها فقط به‌صورت offscreen آزمایش شده‌اند.

## دستورهای تست

```bash
./.venv/bin/python tests/run_tests.py                       # ۲۴۲ تست
./.venv/bin/python tests/run_tests.py --only test_session
./.venv/bin/python tests/run_tests.py --only test_web       # تست رابط وب
./.venv/bin/python tests/run_tests.py --only test_activity  # فید فعالیت
./.venv/bin/python tests/run_tests.py --only test_bidi      # جهت متن ویرایشگر
./.venv/bin/python tests/run_tests.py --only test_sync      # سینک S3 و قفل
QT_QPA_PLATFORM=offscreen ./.venv/bin/python tests/test_ui_smoke.py
./.venv/bin/python tools/smoke_e2e.py
./.venv/bin/python tools/smoke_mcp.py
./.venv/bin/python tools/build_windows_portable.py --check  # CHECK OK
```

تست آینه‌ی واقعی Joplin اختیاری و فقط‌خواندنی است:

```bash
SECURE_VAULT_REAL_MIRROR=1 ./.venv/bin/python tests/run_tests.py --only test_real_mirror_invariants
```
