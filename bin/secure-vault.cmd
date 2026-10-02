@echo off
rem Secure Vault launcher for a Windows checkout (see docs/WINDOWS.md).
rem Uses the checkout's own .venv; run tools\bootstrap.sh (git-bash) or
rem "uv venv && uv pip install -r requirements.txt" once before the first run.
setlocal
set "HERE=%~dp0.."
set "PYTHONPATH=%HERE%\src"
if exist "%HERE%\.venv\Scripts\python.exe" (
  set "PY=%HERE%\.venv\Scripts\python.exe"
) else (
  set "PY=python"
)
"%PY%" -m vault %*
endlocal
