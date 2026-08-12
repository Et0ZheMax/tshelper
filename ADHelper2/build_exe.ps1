$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Test-Path '.venv\Scripts\python.exe')) {
    py -3 -m venv .venv
}
& .venv\Scripts\python.exe -m pip install --upgrade pip
& .venv\Scripts\python.exe -m pip install -r requirements-dev.txt
& .venv\Scripts\pyinstaller.exe `
    --noconfirm --clean --windowed --name ADHelper2 `
    --collect-all PySide6 `
    --add-data "adhelper\scripts;adhelper\scripts" `
    --add-data "adhelper\templates;adhelper\templates" `
    main.py
Write-Host "Готово: dist\ADHelper2\ADHelper2.exe" -ForegroundColor Green
