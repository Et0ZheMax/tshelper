param(
    [string]$OutputDirectory = "dist"
)

$ErrorActionPreference = "Stop"

function Get-PortableSha256 {
    param([string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($stream)) -replace "-", "").ToLowerInvariant()
    } finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$version = & python -c "import sys; sys.path.insert(0, 'src'); from tshelper.version import __version__; print(__version__)"
if ($LASTEXITCODE -ne 0 -or -not $version) {
    throw "Не удалось определить версию TSHelper"
}

$outputRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputDirectory))
$expectedRoot = [System.IO.Path]::GetFullPath($repositoryRoot) + [System.IO.Path]::DirectorySeparatorChar
if (-not $outputRoot.StartsWith($expectedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Каталог сборки должен находиться внутри репозитория: $outputRoot"
}

$packageName = "TSHelper-v$version"
$stage = Join-Path $outputRoot $packageName
$archive = Join-Path $outputRoot "$packageName-portable.zip"
$extensionManifestPath = Join-Path $repositoryRoot "extensions\tshelper-glpi-inventory-bridge\manifest.json"
$extensionVersion = (Get-Content -Raw -LiteralPath $extensionManifestPath | ConvertFrom-Json).version
if (-not $extensionVersion) { throw "Не удалось определить версию GLPI Inventory Bridge" }
$extensionArchive = Join-Path $outputRoot "TSHelper-GLPI-Inventory-Bridge-v$extensionVersion.zip"

if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
if (Test-Path -LiteralPath $extensionArchive) { Remove-Item -LiteralPath $extensionArchive -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$directories = @("src", "apps", "assets", "config", "scripts", "extensions")
foreach ($directory in $directories) {
    $sourceDirectory = Join-Path $repositoryRoot $directory
    $targetDirectory = Join-Path $stage $directory
    New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
    Get-ChildItem -LiteralPath $sourceDirectory -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $targetDirectory -Recurse -Force
    }
}

$files = @("README.md", "CHANGELOG.md", "SECURITY.md", "requirements.txt", "pyproject.toml")
foreach ($file in $files) {
    Copy-Item -LiteralPath (Join-Path $repositoryRoot $file) -Destination $stage
}

Copy-Item -LiteralPath (Join-Path $repositoryRoot "scripts\run_tshelper.bat") -Destination (Join-Path $stage "run_tshelper.bat")
$excludedDirectoryNames = @("__pycache__", ".pytest_cache", ".mypy_cache", ".venv", "venv")
Get-ChildItem -LiteralPath $stage -Directory -Recurse | Where-Object {
    $_.Name -in $excludedDirectoryNames -or $_.Name.EndsWith(".egg-info", [System.StringComparison]::OrdinalIgnoreCase)
} | Sort-Object { $_.FullName.Length } -Descending | Remove-Item -Recurse -Force
$manifestEntries = Get-ChildItem -LiteralPath $stage -File -Recurse | ForEach-Object {
    [pscustomobject]@{
        path = $_.FullName.Substring($stage.Length + 1).Replace("\", "/")
        sha256 = Get-PortableSha256 $_.FullName
        size = $_.Length
    }
} | Sort-Object path
$manifest = [pscustomobject]@{
    format = 1
    version = $version
    files = @($manifestEntries)
}
$manifestJson = $manifest | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText(
    (Join-Path $stage "integrity-manifest.json"),
    $manifestJson,
    (New-Object System.Text.UTF8Encoding($false))
)
Compress-Archive -LiteralPath $stage -DestinationPath $archive -CompressionLevel Optimal
Compress-Archive -Path (Join-Path $repositoryRoot "extensions\tshelper-glpi-inventory-bridge\*") -DestinationPath $extensionArchive -CompressionLevel Optimal
Write-Output $archive
Write-Output $extensionArchive
