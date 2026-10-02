@echo off
rem Secure Vault web UI server — checkout or portable build.
rem Prints the URL plus a one-time access token on stderr.
setlocal
set "HERE=%~dp0.."
set "PYTHONPATH=%HERE%\src"
if exist "%HERE%\python.exe" (
  set "PY=%HERE%\python.exe"
) else if exist "%HERE%\.venv\Scripts\python.exe" (
  set "PY=%HERE%\.venv\Scripts\python.exe"
) else (
  set "PY=python"
)
"%PY%" -m vault.web %*
endlocal
