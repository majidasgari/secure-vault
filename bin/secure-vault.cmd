@echo off
rem Secure Vault launcher — works from a checkout AND from the portable build.
rem
rem Layout detection (docs/WINDOWS.md §2/§3):
rem   * portable\win\bin\secure-vault.cmd  -> uses ..\python.exe (the embedded interpreter)
rem   * <repo>\bin\secure-vault.cmd        -> uses ..\.venv\Scripts\python.exe, else python
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
"%PY%" -m vault %*
endlocal
