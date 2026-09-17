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
* ایمپورتر آینه‌ی Joplin (خواندن فقط‌خواندنی، idempotent، بازنویسی لینک‌ها به
  `vault:/attachments/...`).
* بسته‌بندی: `tools/bootstrap.sh`، لانچرها، نصب دسکتاپ، سازنده‌ی portable ویندوز،
  `pyproject.toml` و مستندات.

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

## دستورهای تست

```bash
./.venv/bin/python tests/run_tests.py                       # ۲۰۰ تست
./.venv/bin/python tests/run_tests.py --only test_session
QT_QPA_PLATFORM=offscreen ./.venv/bin/python tests/test_ui_smoke.py
./.venv/bin/python tools/smoke_e2e.py
./.venv/bin/python tools/smoke_mcp.py
./.venv/bin/python tools/build_windows_portable.py --check  # CHECK OK
```

تست آینه‌ی واقعی Joplin اختیاری و فقط‌خواندنی است:

```bash
SECURE_VAULT_REAL_MIRROR=1 ./.venv/bin/python tests/run_tests.py --only test_real_mirror_invariants
```
