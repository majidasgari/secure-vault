@echo off
rem Secure Vault web UI server for a Windows checkout (prints the token URL on stderr).
setlocal
set "HERE=%~dp0.."
set "PYTHONPATH=%HERE%\src"
if exist "%HERE%\.venv\Scripts\python.exe" (
  set "PY=%HERE%\.venv\Scripts\python.exe"
) else (
  set "PY=python"
)
"%PY%" -m vault.web %*
endlocal
