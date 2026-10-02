@echo off
rem Secure Vault restore launcher — works from a checkout AND from the portable build.
rem
rem Layout detection (docs/WINDOWS.md §2/§3):
rem   * portable\win\bin\secure-vault-import.cmd  -> uses ..\python.exe (embedded interpreter)
rem   * <repo>\bin\secure-vault-import.cmd        -> uses ..\.venv\Scripts\python.exe, else python
rem
rem Restores the vault that already lives in an S3 bucket (docs/SYNC.md §8), e.g.
rem   secure-vault-import.cmd --home D:\Vault --bucket my-bucket --prefix sync --check
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
"%PY%" -m vault.import_cli %*
endlocal
