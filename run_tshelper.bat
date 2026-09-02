@echo off
setlocal
set "TSHELPER_ROOT=%~dp0"
if not exist "%TSHELPER_ROOT%pyproject.toml" set "TSHELPER_ROOT=%~dp0\.."
cd /d "%TSHELPER_ROOT%"

if not exist ".venv\Scripts\python.exe" (
  py -3.11 -m venv .venv 2>nul || py -3 -m venv .venv
  if errorlevel 1 exit /b 1
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  ".venv\Scripts\python.exe" -m pip install -e . --no-deps
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%TSHELPER_ROOT%scripts\create_tshelper_shortcut.ps1" -RootPath "%TSHELPER_ROOT%" >nul 2>&1
start "TSHelper" ".venv\Scripts\pythonw.exe" -m tshelper
