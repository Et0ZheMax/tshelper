param(
    [Parameter(Mandatory = $true)][string]$SourceDirectory,
    [Parameter(Mandatory = $true)][string]$TargetDirectory,
    [Parameter(Mandatory = $true)][int]$WaitForPid,
    [Parameter(Mandatory = $true)][string]$ExpectedVersion,
    [Parameter(Mandatory = $true)][string]$LauncherPath,
    [Parameter(Mandatory = $true)][string]$LogPath,
    [switch]$Elevated
)

$ErrorActionPreference = "Stop"
$managedPaths = @(
    "src", "apps", "assets", "config", "scripts",
    "README.md", "CHANGELOG.md", "SECURITY.md", "requirements.txt",
    "pyproject.toml", "run_tshelper.bat"
)
$installedPaths = [System.Collections.Generic.List[string]]::new()
$backedUpPaths = [System.Collections.Generic.List[string]]::new()

function Write-UpdateLog {
    param([string]$Message)
    $parent = Split-Path -Parent $LogPath
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Add-Content -LiteralPath $LogPath -Encoding UTF8 -Value "$(Get-Date -Format s) $Message"
}

function Get-NormalizedPath {
    param([string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
}

function Assert-ChildPath {
    param([string]$Root, [string]$Candidate)
    $normalizedRoot = (Get-NormalizedPath $Root) + [System.IO.Path]::DirectorySeparatorChar
    $normalizedCandidate = Get-NormalizedPath $Candidate
    if (-not $normalizedCandidate.StartsWith($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Путь выходит за разрешённый каталог: $normalizedCandidate"
    }
    return $normalizedCandidate
}

function Test-TargetWritable {
    param([string]$Root)
    $probe = Join-Path $Root ".tshelper-update-write-$PID.tmp"
    try {
        [System.IO.File]::WriteAllText($probe, "test")
        return $true
    } catch {
        return $false
    } finally {
        if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Force }
    }
}

function Quote-ProcessArgument {
    param([string]$Value)
    if ($Value.Contains('"')) { throw "Недопустимая кавычка в аргументе процесса" }
    return '"' + $Value + '"'
}

function Start-ElevatedUpdater {
    $arguments = @(
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", (Quote-ProcessArgument $PSCommandPath),
        "-SourceDirectory", (Quote-ProcessArgument $SourceDirectory),
        "-TargetDirectory", (Quote-ProcessArgument $TargetDirectory),
        "-WaitForPid", [string]$WaitForPid,
        "-ExpectedVersion", (Quote-ProcessArgument $ExpectedVersion),
        "-LauncherPath", (Quote-ProcessArgument $LauncherPath),
        "-LogPath", (Quote-ProcessArgument $LogPath),
        "-Elevated"
    ) -join " "
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $arguments -WindowStyle Hidden | Out-Null
}

function Restore-Backup {
    param([string]$BackupRoot, [string]$TargetRoot)
    Write-UpdateLog "Начат откат файлов"
    foreach ($relativePath in $installedPaths) {
        $targetPath = Assert-ChildPath $TargetRoot (Join-Path $TargetRoot $relativePath)
        if (Test-Path -LiteralPath $targetPath) {
            Remove-Item -LiteralPath $targetPath -Recurse -Force
        }
    }
    foreach ($relativePath in $backedUpPaths) {
        $backupPath = Assert-ChildPath $BackupRoot (Join-Path $BackupRoot $relativePath)
        $targetPath = Assert-ChildPath $TargetRoot (Join-Path $TargetRoot $relativePath)
        if (Test-Path -LiteralPath $backupPath) {
            Copy-Item -LiteralPath $backupPath -Destination $targetPath -Recurse -Force
        }
    }
    Write-UpdateLog "Откат файлов завершён"
}

$sourceRoot = Get-NormalizedPath $SourceDirectory
$targetRoot = Get-NormalizedPath $TargetDirectory
$launcher = Get-NormalizedPath $LauncherPath
$separator = [System.IO.Path]::DirectorySeparatorChar

if ($sourceRoot -eq $targetRoot) { throw "Источник обновления совпадает с каталогом установки" }
if (
    $sourceRoot.StartsWith($targetRoot + $separator, [System.StringComparison]::OrdinalIgnoreCase) -or
    $targetRoot.StartsWith($sourceRoot + $separator, [System.StringComparison]::OrdinalIgnoreCase)
) {
    throw "Источник обновления и каталог установки не должны пересекаться"
}
$sourceVersionPath = Join-Path $sourceRoot "src\tshelper\version.py"
if (-not (Test-Path -LiteralPath $sourceVersionPath -PathType Leaf)) {
    throw "Источник обновления не прошёл проверку структуры"
}
$versionText = [System.IO.File]::ReadAllText($sourceVersionPath, [System.Text.Encoding]::UTF8)
$versionMatch = [regex]::Match($versionText, '(?m)^__version__\s*=\s*["'']([^"'']+)["'']')
if (-not $versionMatch.Success -or $versionMatch.Groups[1].Value -ne $ExpectedVersion) {
    throw "Версия источника не совпадает с ожидаемой версией $ExpectedVersion"
}
if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot "run_tshelper.bat") -PathType Leaf)) {
    throw "В источнике обновления отсутствует run_tshelper.bat"
}
if (-not (Test-Path -LiteralPath (Join-Path $targetRoot "src\tshelper\version.py") -PathType Leaf)) {
    throw "Каталог установки TSHelper не прошёл проверку структуры"
}
if ((Split-Path -Parent $launcher) -ine $targetRoot) {
    throw "Launcher должен находиться непосредственно в каталоге установки"
}

if (-not (Test-TargetWritable $targetRoot)) {
    if ($Elevated) { throw "Нет прав на запись в каталог установки даже после повышения прав" }
    Write-UpdateLog "Запрошено повышение прав для обновления $ExpectedVersion"
    Start-ElevatedUpdater
    exit 0
}

$updatesBase = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:TEMP }
$updatesRoot = Join-Path $updatesBase "TSHelper\updates"
$backupRoot = Join-Path $updatesRoot "backups\$ExpectedVersion-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$backupRoot = Get-NormalizedPath $backupRoot
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null

try {
    Write-UpdateLog "Ожидание завершения процесса $WaitForPid"
    Wait-Process -Id $WaitForPid -Timeout 120 -ErrorAction SilentlyContinue
    if (Get-Process -Id $WaitForPid -ErrorAction SilentlyContinue) {
        throw "TSHelper не завершился за 120 секунд"
    }

    Write-UpdateLog "Создание резервной копии перед обновлением до $ExpectedVersion"
    foreach ($relativePath in $managedPaths) {
        $sourcePath = Assert-ChildPath $sourceRoot (Join-Path $sourceRoot $relativePath)
        if (-not (Test-Path -LiteralPath $sourcePath)) {
            throw "В обновлении отсутствует обязательный путь: $relativePath"
        }
        $targetPath = Assert-ChildPath $targetRoot (Join-Path $targetRoot $relativePath)
        if (Test-Path -LiteralPath $targetPath) {
            $backupPath = Assert-ChildPath $backupRoot (Join-Path $backupRoot $relativePath)
            $backupParent = Split-Path -Parent $backupPath
            if ($backupParent) { New-Item -ItemType Directory -Path $backupParent -Force | Out-Null }
            Copy-Item -LiteralPath $targetPath -Destination $backupPath -Recurse -Force
            $backedUpPaths.Add($relativePath)
        }
    }

    Write-UpdateLog "Замена управляемых файлов"
    foreach ($relativePath in $managedPaths) {
        $sourcePath = Assert-ChildPath $sourceRoot (Join-Path $sourceRoot $relativePath)
        $targetPath = Assert-ChildPath $targetRoot (Join-Path $targetRoot $relativePath)
        if (Test-Path -LiteralPath $targetPath) {
            Remove-Item -LiteralPath $targetPath -Recurse -Force
        }
        Copy-Item -LiteralPath $sourcePath -Destination $targetPath -Recurse -Force
        $installedPaths.Add($relativePath)
    }

    $venvPython = Join-Path $targetRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
        Write-UpdateLog "Синхронизация зависимостей виртуального окружения"
        & $venvPython -m pip install -r (Join-Path $targetRoot "requirements.txt")
        if ($LASTEXITCODE -ne 0) { throw "pip install завершился с кодом $LASTEXITCODE" }
        & $venvPython -m pip install -e $targetRoot --no-deps
        if ($LASTEXITCODE -ne 0) { throw "Обновление editable-пакета завершилось с кодом $LASTEXITCODE" }
    }

    Write-UpdateLog "Обновление до $ExpectedVersion успешно установлено"
    Start-Process -FilePath $launcher -WorkingDirectory $targetRoot -WindowStyle Hidden
    exit 0
} catch {
    $message = $_.Exception.Message
    Write-UpdateLog "Ошибка обновления: $message"
    try { Restore-Backup -BackupRoot $backupRoot -TargetRoot $targetRoot } catch {
        Write-UpdateLog "Ошибка отката: $($_.Exception.Message)"
    }
    if (Test-Path -LiteralPath $launcher -PathType Leaf) {
        Start-Process -FilePath $launcher -WorkingDirectory $targetRoot -WindowStyle Hidden
    }
    try {
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show(
            "Не удалось установить обновление TSHelper. Предыдущая версия восстановлена.`n`n$message`n`nЖурнал: $LogPath",
            "Ошибка обновления TSHelper",
            "OK",
            "Error"
        ) | Out-Null
    } catch { }
    exit 1
}
