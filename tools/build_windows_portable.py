#!/usr/bin/env python3
"""Build a Windows portable folder for Secure Vault from this Linux checkout (SPEC/05 §5).

Two modes:

* ``--check`` — **offline validation only** (the mode that must pass on this box):
  validates the repository layout, that every third-party import in ``src/vault`` is
  covered by ``requirements.txt``, that the launchers and entry modules exist, and
  that the destination directory is writable. Prints ``CHECK OK`` and exits 0.

* real build (documented; needs the mirror/python.org reachable): downloads the
  embeddable CPython zip, enables ``import site`` in ``python*._pth``, cross-installs
  the ``win_amd64`` wheels into ``Lib/site-packages`` with
  ``pip --only-binary=:all: --platform win_amd64`` (it refuses to build when a
  dependency has no wheel), copies ``src/ i18n/ assets/ bin/`` into the folder and
  writes ``README.txt`` plus the ``.cmd`` launchers. ``--force`` wipes the destination
  first. The embeddable interpreter is a Windows binary and cannot be executed here,
  so the wheels are installed by the *host* pip with cross-platform flags; ``pip``
  itself is installed into the folder the same way (``get-pip.py`` cannot run on
  Linux). See ``docs/WINDOWS.md``.
"""

from __future__ import annotations

import argparse
import ast
import configparser
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
REQUIREMENTS = REPO_ROOT / "requirements.txt"
DEFAULT_DEST = "portable/win"
DEFAULT_PYTHON_VERSION = "3.12.10"
DEFAULT_INDEX_URL = "https://mirror-pypi.runflare.com/simple/"
DEFAULT_TRUSTED_HOST = "mirror-pypi.runflare.com"
EMBED_URL = "https://www.python.org/ftp/python/{version}/python-{version}-embed-amd64.zip"

# Import name -> distribution name, for the coverage check.
IMPORT_TO_DIST = {
    "PySide6": "PySide6",
    "cryptography": "cryptography",
    "argon2": "argon2-cffi",
    "markdown_it": "markdown-it-py",
    "pygments": "Pygments",
}

# Lazy/opt-in imports that are intentionally not in requirements.txt.
OPTIONAL_IMPORTS = {
    "sentence_transformers": "sentence-transformers (requirements-semantic.txt)",
}

FIRST_PARTY = {"vault"}

REQUIRED_LAYOUT = (
    "requirements.txt",
    "requirements-semantic.txt",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "bin/secure-vault",
    "bin/secure-vault-mcp",
    "src/vault/__init__.py",
    "src/vault/__main__.py",
    "src/vault/mcp.py",
    "src/vault/gui.py",
    "src/vault/daemon.py",
    "i18n/fa.json",
    "i18n/en.json",
    "assets/icon.svg",
)


def _normalize_dist(name: str) -> str:
    """Return the PEP 503 normalized distribution name."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def parse_requirements(path: Path) -> dict[str, str]:
    """Return ``{normalized_name: original_line}`` for a requirements file."""
    result: dict[str, str] = {}
    if not path.is_file():
        return result
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match:
            result[_normalize_dist(match.group(1))] = line
    return result


def collect_imports(root: Path) -> set[str]:
    """Return the top-level module names imported by every ``.py`` file under ``root``."""
    modules: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as exc:  # pragma: no cover - defensive
            raise SystemExit(f"cannot parse {path}: {exc}") from exc
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    modules.add(node.module.split(".")[0])
    return modules


def check_layout() -> list[str]:
    """Return a list of layout problems (empty when the layout is complete)."""
    problems: list[str] = []
    for relative in REQUIRED_LAYOUT:
        if not (REPO_ROOT / relative).exists():
            problems.append(f"missing required file: {relative}")
    if not SRC_ROOT.is_dir():
        problems.append(f"missing source tree: {SRC_ROOT}")
    return problems


def check_imports() -> list[str]:
    """Return third-party imports not covered by requirements.txt."""
    requirements = parse_requirements(REQUIREMENTS)
    stdlib = set(sys.stdlib_module_names)
    problems: list[str] = []
    for module in sorted(collect_imports(SRC_ROOT)):
        if module in stdlib or module in FIRST_PARTY or module.startswith("_"):
            continue
        if module in OPTIONAL_IMPORTS:
            continue
        dist = IMPORT_TO_DIST.get(module)
        if dist is None:
            problems.append(f"{module}: no distribution mapping (update IMPORT_TO_DIST)")
            continue
        if _normalize_dist(dist) not in requirements:
            problems.append(f"{module}: distribution {dist!r} is not in requirements.txt")
    return problems


def check_dest_writable(dest: Path) -> list[str]:
    """Return a problem when ``dest`` cannot be created/written."""
    if dest.exists():
        if not dest.is_dir():
            return [f"destination exists and is not a directory: {dest}"]
        if not os.access(dest, os.W_OK):
            return [f"destination is not writable: {dest}"]
        return []
    probe = dest
    while not probe.exists():
        if probe.parent == probe:
            return [f"no existing ancestor for destination: {dest}"]
        probe = probe.parent
    if not os.access(probe, os.W_OK):
        return [f"cannot create destination below {probe}: not writable"]
    return []


def run_check(dest: Path) -> int:
    """Run the offline validation and print ``CHECK OK`` or the problems."""
    problems = check_layout() + check_imports() + check_dest_writable(dest)
    if problems:
        print("CHECK FAILED")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"layout: {len(REQUIRED_LAYOUT)} required paths present")
    print(f"imports: every third-party import is covered by {REQUIREMENTS.name}")
    print(f"destination: {dest} is writable")
    print("CHECK OK")
    return 0


# --------------------------------------------------------------------------- real build


def read_pip_config() -> tuple[str, str]:
    """Return ``(index_url, trusted_host)`` from the venv pip.conf or the defaults."""
    conf = REPO_ROOT / ".venv" / "pip.conf"
    if conf.is_file():
        parser = configparser.ConfigParser()
        try:
            parser.read(conf, encoding="utf-8")
            index = parser.get("global", "index-url", fallback="")
            host = parser.get("global", "trusted-host", fallback="")
            if index:
                return index, host or DEFAULT_TRUSTED_HOST
        except (configparser.Error, OSError):  # pragma: no cover - fall back
            pass
    return DEFAULT_INDEX_URL, DEFAULT_TRUSTED_HOST


def download(url: str, dest: Path) -> None:
    """Download ``url`` to ``dest`` with urllib (no third-party dependency)."""
    print(f"downloading {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "secure-vault-builder"})
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            with open(dest, "wb") as handle:
                shutil.copyfileobj(response, handle)
    except (urllib.error.URLError, OSError) as exc:
        raise SystemExit(f"download failed: {url}: {exc}") from exc


def prepare_dest(dest: Path, *, force: bool) -> None:
    """Create/clean the destination, refusing obviously dangerous targets."""
    resolved = dest.resolve()
    if resolved in (Path("/"), REPO_ROOT.resolve()):
        raise SystemExit(f"refusing to use {resolved} as the build destination")
    if force and dest.exists():
        print(f"removing existing destination {dest}")
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)


def fetch_embeddable(dest: Path, version: str) -> None:
    """Download and unpack the embeddable CPython distribution into ``dest``."""
    url = EMBED_URL.format(version=version)
    with tempfile.TemporaryDirectory(prefix="sv-win-embed-") as tmp:
        archive = Path(tmp) / f"python-{version}-embed-amd64.zip"
        download(url, archive)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(dest)
    print(f"unpacked the embeddable CPython {version} into {dest}")


def enable_site(dest: Path) -> None:
    """Uncomment ``import site`` and add ``Lib/site-packages`` + ``src`` to the ``_pth``."""
    pth_files = sorted(dest.glob("python*._pth"))
    if not pth_files:
        raise SystemExit(f"no python*._pth found in {dest} (bad embeddable download?)")
    pth = pth_files[0]
    lines = pth.read_text(encoding="utf-8").splitlines()
    output: list[str] = []
    saw_site = False
    for line in lines:
        stripped = line.strip()
        if stripped in ("#import site", "# import site"):
            output.append("import site")
            saw_site = True
        else:
            output.append(line)
            if stripped == "import site":
                saw_site = True
    if not saw_site:
        output.append("import site")
    for entry in (r"Lib\site-packages", "src"):
        if entry not in output:
            output.append(entry)
    pth.write_text("\n".join(output) + "\n", encoding="utf-8")
    print(f"enabled site imports and added app paths to {pth.name}")


def pip_install(dest: Path, version: str, index_url: str, trusted_host: str) -> None:
    """Cross-install the Windows wheels (and pip) into ``Lib/site-packages``."""
    site_packages = dest / "Lib" / "site-packages"
    site_packages.mkdir(parents=True, exist_ok=True)
    common = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--target",
        str(site_packages),
        "--only-binary=:all:",
        "--platform",
        "win_amd64",
        "--python-version",
        version,
        "--implementation",
        "cp",
        "--index-url",
        index_url,
    ]
    if trusted_host:
        common += ["--trusted-host", trusted_host]
    print("installing pip into the portable folder")
    pip_result = subprocess.run([*common, "pip"], check=False)
    if pip_result.returncode != 0:
        raise SystemExit(
            "refusing to build: could not install pip for win_amd64 (no wheel?)"
        )
    print(f"installing {REQUIREMENTS.name} wheels for win_amd64")
    result = subprocess.run([*common, "-r", str(REQUIREMENTS)], check=False)
    if result.returncode != 0:
        raise SystemExit(
            "refusing to build: a dependency has no win_amd64 wheel "
            "(pip --only-binary=:all: failed). The portable build must not compile."
        )
    print("installed all runtime wheels into Lib/site-packages")


def copy_app(dest: Path) -> None:
    """Copy the runtime tree into the portable folder."""
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
    for name in ("src", "i18n", "assets", "bin"):
        source = REPO_ROOT / name
        if not source.is_dir():
            raise SystemExit(f"missing source directory: {source}")
        shutil.copytree(source, dest / name, dirs_exist_ok=True, ignore=ignore)
        print(f"copied {name}/ into the portable folder")


def _write_crlf(path: Path, text: str) -> None:
    """Write ``text`` with Windows line endings."""
    path.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))


def write_launchers(dest: Path) -> None:
    """Write the ``.cmd``/``.bat`` launchers for Windows."""
    run = """@echo off
setlocal
set "HERE=%~dp0"
set "PYTHONPATH=%HERE%src"
"%HERE%python.exe" -m vault %*
endlocal
"""
    mcp = """@echo off
setlocal
set "HERE=%~dp0"
set "PYTHONPATH=%HERE%src"
if "%SECURE_VAULT_DEBUG%"=="1" (
  "%HERE%python.exe" -m vault.mcp --debug %*
) else (
  "%HERE%python.exe" -m vault.mcp %*
)
endlocal
"""
    _write_crlf(dest / "run.cmd", run)
    _write_crlf(dest / "run.bat", run)
    _write_crlf(dest / "secure-vault.cmd", run)
    _write_crlf(dest / "secure-vault-mcp.cmd", mcp)
    print("wrote run.cmd, run.bat, secure-vault.cmd, secure-vault-mcp.cmd")


README_TXT = """\
Secure Vault — portable Windows build
=====================================

فارسی:
-----
این پوشه نسخه‌ی portable گاوصندوق برای ویندوز است. برای اجرا:

  1. روی run.cmd (یا secure-vault.cmd) دوبار کلیک کنید.
  2. در اجرای اول، پوشه‌ی گاوصندوق (vault home) و گذرواژه‌ی اصلی را انتخاب/وارد کنید.
     گذرواژه ذخیره نمی‌شود و هیچ راهی برای بازیابی آن وجود ندارد؛ آن را جای امنی
     نگه دارید.
  3. برای اتصال ایجنت‌ها، مسیر کامل secure-vault-mcp.cmd را به‌عنوان فرمان MCP در
     Hermes ثبت کنید (docs/MCP.md را ببینید).

English:
--------
This folder is the portable Windows build of Secure Vault. To run it:

  1. Double-click run.cmd (or secure-vault.cmd).
  2. On first run, choose the vault home folder and set the master password. The
     password is never stored and cannot be recovered — keep it safe.
  3. To give agents access, register the full path of secure-vault-mcp.cmd as the
     MCP server command in Hermes (see docs/MCP.md).

Notes:
  * The vault home must be chosen on first run; the default is a per-user folder and
    is configurable in Settings. Nothing secret is stored next to this program.
  * Runtime data (the decrypted store, socket, token) lives in the user's runtime
    directory, never in the vault home.
  * This build was produced on Linux and has NOT been verified on a real Windows
    machine yet (see docs/WINDOWS.md).
"""


def write_readme(dest: Path) -> None:
    """Write ``README.txt`` with the run instructions (Persian + English)."""
    _write_crlf(dest / "README.txt", README_TXT)
    print("wrote README.txt")


def build(dest: Path, version: str, *, force: bool) -> int:
    """Run the real portable build and return the exit code."""
    index_url, trusted_host = read_pip_config()
    prepare_dest(dest, force=force)
    fetch_embeddable(dest, version)
    enable_site(dest)
    pip_install(dest, version, index_url, trusted_host)
    copy_app(dest)
    write_launchers(dest)
    write_readme(dest)
    print(f"\nportable Windows build ready: {dest}")
    print("NOTE: produced on Linux; not verified on Windows yet (docs/WINDOWS.md).")
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the builder command line."""
    parser = argparse.ArgumentParser(
        prog="build_windows_portable.py",
        description="Build a Windows portable Secure Vault folder (SPEC/05 §5).",
    )
    parser.add_argument(
        "--dest",
        default=DEFAULT_DEST,
        help=f"output folder (default: {DEFAULT_DEST})",
    )
    parser.add_argument(
        "--python-version",
        default=DEFAULT_PYTHON_VERSION,
        help=f"embeddable CPython version (default: {DEFAULT_PYTHON_VERSION})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="offline validation only; prints CHECK OK",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="wipe the destination before building",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the builder (or the check) and return the process exit code."""
    args = _parse_args(argv)
    dest = Path(args.dest)
    if not dest.is_absolute():
        dest = REPO_ROOT / dest
    if args.check:
        return run_check(dest)
    return build(dest, args.python_version, force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
