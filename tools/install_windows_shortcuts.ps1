# Secure Vault — install per-user Windows shortcuts (Start menu + Startup / autostart).
#
# Creates two shortcuts that both run the portable GUI without a console window:
#   * %APPDATA%\Microsoft\Windows\Start Menu\Programs\Secure Vault.lnk   (apps list / search)
#   * %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Secure Vault.lnk   (runs at logon)
#
# The target is the portable build's embedded interpreter, so the folder must exist:
#   python tools/build_windows_portable.py --dest portable/win
#
# Usage (no admin needed — everything is per-user):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\install_windows_shortcuts.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\install_windows_shortcuts.ps1 -Remove
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\install_windows_shortcuts.ps1 -NoStartup

[CmdletBinding()]
param(
    [string]$PortableDir,
    [string]$IconPath,
    [switch]$NoStartup,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
if (-not $PortableDir) { $PortableDir = Join-Path $repo "portable\win" }
if (-not $IconPath) { $IconPath = Join-Path $repo "assets\secure-vault.ico" }

$exe = Join-Path $PortableDir "pythonw.exe"          # pythonw = no console window
$arguments = "-m vault"                              # src/ is on the embedded ._pth path
$programs = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$links = @((Join-Path $programs "Secure Vault.lnk"))
if (-not $NoStartup) {
    $links += (Join-Path $programs "Startup\Secure Vault.lnk")
}

if ($Remove) {
    foreach ($link in $links) {
        if (Test-Path -LiteralPath $link) {
            Remove-Item -LiteralPath $link -Force
            Write-Output "removed $link"
        }
    }
    return
}

foreach ($path in @($exe, $IconPath)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "missing: $path (build the portable folder first)" }
}

$shell = New-Object -ComObject WScript.Shell
foreach ($link in $links) {
    $shortcut = $shell.CreateShortcut($link)
    $shortcut.TargetPath = $exe
    $shortcut.Arguments = $arguments
    $shortcut.WorkingDirectory = (Resolve-Path -LiteralPath $PortableDir).Path
    $shortcut.IconLocation = "$((Resolve-Path -LiteralPath $IconPath).Path),0"
    $shortcut.Description = "Secure Vault - encrypted personal vault"
    $shortcut.WindowStyle = 1
    $shortcut.Save()
    $check = $shell.CreateShortcut($link)                # read back what Windows stored
    if (-not (Test-Path -LiteralPath $link)) { throw "shortcut not created: $link" }
    Write-Output ("{0}`n  target: {1} {2}`n  workdir: {3}`n  icon: {4}" -f `
        $link, $check.TargetPath, $check.Arguments, $check.WorkingDirectory, $check.IconLocation)
}
