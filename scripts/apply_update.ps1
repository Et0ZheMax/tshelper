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
    "src", "apps", "assets", "config", "scripts", "extensions",
    "README.md", "CHANGELOG.md", "SECURITY.md", "requirements.txt",
    "pyproject.toml", "run_tshelper.bat", "integrity-manifest.json"
)
$installedPaths = [System.Collections.Generic.List[string]]::new()
$backedUpPaths = [System.Collections.Generic.List[string]]::new()
$progressForm = $null
$progressBar = $null
$progressStatus = $null
$progressPercent = $null

function Write-UpdateLog {
    param([string]$Message)
    $parent = Split-Path -Parent $LogPath
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Add-Content -LiteralPath $LogPath -Encoding UTF8 -Value "$(Get-Date -Format s) $Message"
}

function Initialize-ProgressWindow {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        $script:progressForm = [System.Windows.Forms.Form]::new()
        $script:progressForm.Text = "Обновление TSHelper"
        $script:progressForm.ClientSize = [System.Drawing.Size]::new(520, 230)
        $script:progressForm.StartPosition = "CenterScreen"
        $script:progressForm.FormBorderStyle = "FixedDialog"
        $script:progressForm.MaximizeBox = $false
        $script:progressForm.MinimizeBox = $false
        $script:progressForm.ControlBox = $false
        $script:progressForm.TopMost = $true
        $script:progressForm.BackColor = [System.Drawing.Color]::White

        $title = [System.Windows.Forms.Label]::new()
        $title.Text = "TSHelper $ExpectedVersion"
        $title.Location = [System.Drawing.Point]::new(28, 22)
        $title.Size = [System.Drawing.Size]::new(460, 34)
        $title.Font = [System.Drawing.Font]::new("Segoe UI", 17, [System.Drawing.FontStyle]::Bold)
        $title.ForeColor = [System.Drawing.Color]::FromArgb(32, 52, 82)
        $script:progressForm.Controls.Add($title)

        $subtitle = [System.Windows.Forms.Label]::new()
        $subtitle.Text = "Безопасная установка обновления"
        $subtitle.Location = [System.Drawing.Point]::new(31, 61)
        $subtitle.Size = [System.Drawing.Size]::new(440, 24)
        $subtitle.Font = [System.Drawing.Font]::new("Segoe UI", 10)
        $subtitle.ForeColor = [System.Drawing.Color]::FromArgb(100, 112, 128)
        $script:progressForm.Controls.Add($subtitle)

        $script:progressBar = [System.Windows.Forms.ProgressBar]::new()
        $script:progressBar.Location = [System.Drawing.Point]::new(32, 105)
        $script:progressBar.Size = [System.Drawing.Size]::new(456, 18)
        $script:progressBar.Style = "Continuous"
        $script:progressForm.Controls.Add($script:progressBar)

        $script:progressStatus = [System.Windows.Forms.Label]::new()
        $script:progressStatus.Text = "Подготовка…"
        $script:progressStatus.Location = [System.Drawing.Point]::new(31, 139)
        $script:progressStatus.Size = [System.Drawing.Size]::new(390, 25)
        $script:progressStatus.Font = [System.Drawing.Font]::new("Segoe UI", 10)
        $script:progressStatus.ForeColor = [System.Drawing.Color]::FromArgb(45, 57, 72)
        $script:progressForm.Controls.Add($script:progressStatus)

        $script:progressPercent = [System.Windows.Forms.Label]::new()
        $script:progressPercent.Text = "0%"
        $script:progressPercent.TextAlign = "TopRight"
        $script:progressPercent.Location = [System.Drawing.Point]::new(425, 139)
        $script:progressPercent.Size = [System.Drawing.Size]::new(62, 25)
        $script:progressPercent.Font = [System.Drawing.Font]::new("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $script:progressPercent.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
        $script:progressForm.Controls.Add($script:progressPercent)

        $note = [System.Windows.Forms.Label]::new()
        $note.Text = "TSHelper автоматически запустится после завершения"
        $note.Location = [System.Drawing.Point]::new(31, 184)
        $note.Size = [System.Drawing.Size]::new(456, 24)
        $note.Font = [System.Drawing.Font]::new("Segoe UI", 9)
        $note.ForeColor = [System.Drawing.Color]::FromArgb(125, 135, 148)
        $script:progressForm.Controls.Add($note)

        $script:progressForm.Show()
        [System.Windows.Forms.Application]::DoEvents()
    } catch {
        Write-UpdateLog "Не удалось показать окно прогресса: $($_.Exception.Message)"
        $script:progressForm = $null
    }
}

function Set-UpdateProgress {
    param([string]$Message, [int]$Percent, [switch]$Marquee)
    if ($null -eq $script:progressForm) { return }
    $script:progressStatus.Text = $Message
    if ($Marquee) {
        $script:progressBar.Style = "Marquee"
        $script:progressBar.MarqueeAnimationSpeed = 24
        $script:progressPercent.Text = ""
    } else {
        $script:progressBar.Style = "Continuous"
        $script:progressBar.Value = [Math]::Max(0, [Math]::Min(100, $Percent))
        $script:progressPercent.Text = "$Percent%"
    }
    [System.Windows.Forms.Application]::DoEvents()
}

function Close-ProgressWindow {
    if ($null -ne $script:progressForm) {
        $script:progressForm.Close()
        $script:progressForm.Dispose()
        $script:progressForm = $null
    }
}

function Update-ProgressEvents {
    if ($null -ne $script:progressForm) {
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Invoke-UpdateProcess {
    param([string]$FilePath, [string]$Arguments)
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -WindowStyle Hidden `
        -PassThru
    while (-not $process.HasExited) {
        Update-ProgressEvents
        Start-Sleep -Milliseconds 100
        $process.Refresh()
    }
    return $process.ExitCode
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

function Get-FileSha256 {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "" }
    $stream = [System.IO.File]::OpenRead($Path)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($stream)
        return ([System.BitConverter]::ToString($hash) -replace "-", "").ToLowerInvariant()
    } finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Assert-FileManifest {
    param([string]$Root, [string]$Version)
    $manifestPath = Assert-ChildPath $Root (Join-Path $Root "integrity-manifest.json")
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Отсутствует манифест целостности обновления"
    }
    $manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json
    if ($manifest.format -ne 1 -or [string]$manifest.version -ne $Version -or -not $manifest.files) {
        throw "Некорректный манифест целостности обновления"
    }
    $seen = @{}
    foreach ($entry in $manifest.files) {
        $relativePath = [string]$entry.path
        $expectedHash = ([string]$entry.sha256).ToLowerInvariant()
        if (
            [string]::IsNullOrWhiteSpace($relativePath) -or
            $relativePath -eq "integrity-manifest.json" -or
            $relativePath.Contains("..") -or $relativePath.Contains(":") -or
            $expectedHash -notmatch '^[0-9a-f]{64}$' -or
            $seen.ContainsKey($relativePath)
        ) {
            throw "Некорректная запись манифеста: $relativePath"
        }
        $seen[$relativePath] = $true
        $filePath = Assert-ChildPath $Root (Join-Path $Root $relativePath)
        $actualHash = Get-FileSha256 $filePath
        if ($actualHash -ne $expectedHash) {
            throw "Файл не прошёл проверку целостности: $relativePath"
        }
        Update-ProgressEvents
    }
    Write-UpdateLog "Проверено файлов по манифесту: $($seen.Count)"
}

function Preserve-AdHelperEnvironment {
    param([string]$EnvironmentPath, [string]$PreservedPath)
    if (Test-Path -LiteralPath $PreservedPath) { return }
    if (-not (Test-Path -LiteralPath $EnvironmentPath -PathType Container)) { return }
    $preservedParent = Split-Path -Parent $PreservedPath
    if ($preservedParent) { New-Item -ItemType Directory -Path $preservedParent -Force | Out-Null }
    Move-Item -LiteralPath $EnvironmentPath -Destination $PreservedPath -Force
    Write-UpdateLog "Окружение ADHelper сохранено без переустановки"
}

function Restore-AdHelperEnvironment {
    param([string]$EnvironmentPath, [string]$PreservedPath)
    if (-not (Test-Path -LiteralPath $PreservedPath -PathType Container)) { return }
    if (Test-Path -LiteralPath $EnvironmentPath) {
        Remove-Item -LiteralPath $EnvironmentPath -Recurse -Force
    }
    $environmentParent = Split-Path -Parent $EnvironmentPath
    if ($environmentParent) { New-Item -ItemType Directory -Path $environmentParent -Force | Out-Null }
    Move-Item -LiteralPath $PreservedPath -Destination $EnvironmentPath -Force
    Write-UpdateLog "Окружение ADHelper восстановлено в обновлённое приложение"
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
Assert-FileManifest -Root $sourceRoot -Version $ExpectedVersion
if (-not (Test-Path -LiteralPath (Join-Path $targetRoot "src\tshelper\version.py") -PathType Leaf)) {
    throw "Каталог установки TSHelper не прошёл проверку структуры"
}
$rootLauncher = Get-NormalizedPath (Join-Path $targetRoot "run_tshelper.bat")
$scriptsLauncher = Get-NormalizedPath (Join-Path $targetRoot "scripts\run_tshelper.bat")
if ($launcher -ine $rootLauncher -and $launcher -ine $scriptsLauncher) {
    throw "Указан нестандартный launcher TSHelper"
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
$adHelperEnvironment = Assert-ChildPath $targetRoot (Join-Path $targetRoot "apps\adhelper2\.venv")
$preservedAdHelperEnvironment = Assert-ChildPath $backupRoot (Join-Path $backupRoot "_preserved\adhelper2-venv")
$oldAdHelperRequirements = Assert-ChildPath $targetRoot (Join-Path $targetRoot "apps\adhelper2\requirements.txt")
$newAdHelperRequirements = Assert-ChildPath $sourceRoot (Join-Path $sourceRoot "apps\adhelper2\requirements.txt")
$oldAdHelperRequirementsHash = Get-FileSha256 $oldAdHelperRequirements
$newAdHelperRequirementsHash = Get-FileSha256 $newAdHelperRequirements
$adHelperRequirementsUnchanged = (
    $oldAdHelperRequirementsHash -and
    $newAdHelperRequirementsHash -and
    $oldAdHelperRequirementsHash -eq $newAdHelperRequirementsHash
)
Initialize-ProgressWindow

try {
    Set-UpdateProgress -Message "Завершение работы TSHelper…" -Percent 8
    Write-UpdateLog "Ожидание завершения процесса $WaitForPid"
    $waitDeadline = [DateTime]::UtcNow.AddSeconds(120)
    while (Get-Process -Id $WaitForPid -ErrorAction SilentlyContinue) {
        if ([DateTime]::UtcNow -ge $waitDeadline) {
            throw "TSHelper не завершился за 120 секунд"
        }
        Update-ProgressEvents
        Start-Sleep -Milliseconds 100
    }

    Set-UpdateProgress -Message "Создание резервной копии…" -Percent 22
    Write-UpdateLog "Создание резервной копии перед обновлением до $ExpectedVersion"
    Preserve-AdHelperEnvironment `
        -EnvironmentPath $adHelperEnvironment `
        -PreservedPath $preservedAdHelperEnvironment
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
        Update-ProgressEvents
    }

    Set-UpdateProgress -Message "Замена файлов приложения…" -Percent 52
    Write-UpdateLog "Замена управляемых файлов"
    foreach ($relativePath in $managedPaths) {
        $sourcePath = Assert-ChildPath $sourceRoot (Join-Path $sourceRoot $relativePath)
        $targetPath = Assert-ChildPath $targetRoot (Join-Path $targetRoot $relativePath)
        if (Test-Path -LiteralPath $targetPath) {
            Remove-Item -LiteralPath $targetPath -Recurse -Force
        }
        if (Test-Path -LiteralPath $sourcePath -PathType Container) {
            New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
            Get-ChildItem -LiteralPath $sourcePath -Force | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination $targetPath -Recurse -Force
            }
        } else {
            Copy-Item -LiteralPath $sourcePath -Destination $targetPath -Force
        }
        $installedPaths.Add($relativePath)
        Update-ProgressEvents
    }

    Restore-AdHelperEnvironment `
        -EnvironmentPath $adHelperEnvironment `
        -PreservedPath $preservedAdHelperEnvironment

    $venvPython = Join-Path $targetRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
        Set-UpdateProgress -Message "Обновление компонентов…" -Percent 78 -Marquee
        Write-UpdateLog "Синхронизация зависимостей виртуального окружения"
        $requirementsArguments = "-m pip install -r " + (Quote-ProcessArgument (Join-Path $targetRoot "requirements.txt"))
        $pipExitCode = Invoke-UpdateProcess -FilePath $venvPython -Arguments $requirementsArguments
        if ($pipExitCode -ne 0) { throw "pip install завершился с кодом $pipExitCode" }
        $editableArguments = "-m pip install -e " + (Quote-ProcessArgument $targetRoot) + " --no-deps"
        $editableExitCode = Invoke-UpdateProcess -FilePath $venvPython -Arguments $editableArguments
        if ($editableExitCode -ne 0) {
            throw "Обновление editable-пакета завершилось с кодом $editableExitCode"
        }
    }

    if (Test-Path -LiteralPath $adHelperEnvironment -PathType Container) {
        $adHelperRequirementsMarker = Join-Path $adHelperEnvironment ".requirements.sha256"
        if ($adHelperRequirementsUnchanged) {
            [System.IO.File]::WriteAllText(
                $adHelperRequirementsMarker,
                $newAdHelperRequirementsHash,
                [System.Text.Encoding]::ASCII
            )
            Write-UpdateLog "Зависимости ADHelper не изменились; повторная установка не требуется"
        } elseif (Test-Path -LiteralPath $adHelperRequirementsMarker) {
            Remove-Item -LiteralPath $adHelperRequirementsMarker -Force
            Write-UpdateLog "Состав зависимостей ADHelper изменился; установка будет выполнена при запуске"
        }
    }

    Set-UpdateProgress -Message "Проверка установленных файлов…" -Percent 92 -Marquee
    Assert-FileManifest -Root $targetRoot -Version $ExpectedVersion
    Set-UpdateProgress -Message "Запуск обновлённого TSHelper…" -Percent 94
    Write-UpdateLog "Обновление до $ExpectedVersion успешно установлено"
    Set-UpdateProgress -Message "Обновление успешно установлено" -Percent 100
    Start-Sleep -Milliseconds 650
    Close-ProgressWindow
    Start-Process -FilePath $launcher -WorkingDirectory $targetRoot -WindowStyle Hidden
    exit 0
} catch {
    $message = $_.Exception.Message
    Write-UpdateLog "Ошибка обновления: $message"
    Set-UpdateProgress -Message "Восстановление предыдущей версии…" -Percent 60 -Marquee
    try {
        Preserve-AdHelperEnvironment `
            -EnvironmentPath $adHelperEnvironment `
            -PreservedPath $preservedAdHelperEnvironment
        Restore-Backup -BackupRoot $backupRoot -TargetRoot $targetRoot
        Restore-AdHelperEnvironment `
            -EnvironmentPath $adHelperEnvironment `
            -PreservedPath $preservedAdHelperEnvironment
    } catch {
        Write-UpdateLog "Ошибка отката: $($_.Exception.Message)"
    }
    Close-ProgressWindow
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
