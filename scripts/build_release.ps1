param(
    [string]$OutputDirectory = "dist"
)

$ErrorActionPreference = "Stop"
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
    Copy-Item -LiteralPath (Join-Path $repositoryRoot $directory) -Destination $stage -Recurse
}

$files = @("README.md", "CHANGELOG.md", "SECURITY.md", "requirements.txt", "pyproject.toml")
foreach ($file in $files) {
    Copy-Item -LiteralPath (Join-Path $repositoryRoot $file) -Destination $stage
}

Copy-Item -LiteralPath (Join-Path $repositoryRoot "scripts\run_tshelper.bat") -Destination (Join-Path $stage "run_tshelper.bat")
Get-ChildItem -LiteralPath $stage -Directory -Recurse -Filter "__pycache__" | Remove-Item -Recurse -Force
Compress-Archive -LiteralPath $stage -DestinationPath $archive -CompressionLevel Optimal
Compress-Archive -Path (Join-Path $repositoryRoot "extensions\tshelper-glpi-inventory-bridge\*") -DestinationPath $extensionArchive -CompressionLevel Optimal
Write-Output $archive
Write-Output $extensionArchive
