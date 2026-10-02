@echo off
rem Secure Vault MCP bridge (stdio JSON-RPC) — checkout or portable build.
rem Register the ABSOLUTE path of this file as the MCP server command (docs/MCP.md).
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
if "%SECURE_VAULT_DEBUG%"=="1" (
  "%PY%" -m vault.mcp --debug %*
) else (
  "%PY%" -m vault.mcp %*
)
endlocal
