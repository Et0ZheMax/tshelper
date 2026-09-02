param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath
)

$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath($RootPath)
$pythonw = Join-Path $root ".venv\Scripts\pythonw.exe"
$icon = Join-Path $root "assets\ts-logo.ico"

if (-not (Test-Path -LiteralPath $pythonw -PathType Leaf)) {
    throw "Virtual environment pythonw.exe was not found: $pythonw"
}
if (-not (Test-Path -LiteralPath $icon -PathType Leaf)) {
    throw "TSHelper icon was not found: $icon"
}

$programs = [Environment]::GetFolderPath("Programs")
if (-not $programs) {
    throw "Windows Start Menu directory was not found"
}

$shortcutPath = Join-Path $programs "TSHelper.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $pythonw
$shortcut.Arguments = "-m tshelper"
$shortcut.WorkingDirectory = $root
$shortcut.IconLocation = "$icon,0"
$shortcut.Description = "TSHelper"
$shortcut.WindowStyle = 1
$shortcut.Save()
