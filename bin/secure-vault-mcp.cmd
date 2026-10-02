@echo off
rem Secure Vault MCP bridge for a Windows checkout (stdio JSON-RPC; see docs/MCP.md).
setlocal
set "HERE=%~dp0.."
set "PYTHONPATH=%HERE%\src"
if exist "%HERE%\.venv\Scripts\python.exe" (
  set "PY=%HERE%\.venv\Scripts\python.exe"
) else (
  set "PY=python"
)
if "%SECURE_VAULT_DEBUG%"=="1" (
  "%PY%" -m vault.mcp --debug %*
) else (
  "%PY%" -m vault.mcp %*
)
endlocal
