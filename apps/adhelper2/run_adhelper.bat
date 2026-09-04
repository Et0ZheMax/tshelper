@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  .venv\Scripts\python.exe -c "import sys" >nul 2>&1
  if errorlevel 1 (
    echo ADHelper virtual environment is invalid. Recreating it...
    rmdir /s /q ".venv"
  )
)
if not exist ".venv\Scripts\python.exe" (
  where py >nul 2>&1
  if errorlevel 1 (
    python -m venv .venv
  ) else (
    py -3 -m venv .venv
  )
  if errorlevel 1 goto :bootstrap_error
)

set "REQUIREMENTS_HASH="
for /f "delims=" %%H in ('.venv\Scripts\python.exe -c "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('requirements.txt').read_bytes()).hexdigest())"') do set "REQUIREMENTS_HASH=%%H"
set "INSTALLED_REQUIREMENTS_HASH="
if exist ".venv\.requirements.sha256" set /p INSTALLED_REQUIREMENTS_HASH=<".venv\.requirements.sha256"
set "NEEDS_INSTALL=0"
if not defined REQUIREMENTS_HASH set "NEEDS_INSTALL=1"
if /I not "!INSTALLED_REQUIREMENTS_HASH!"=="!REQUIREMENTS_HASH!" set "NEEDS_INSTALL=1"
.venv\Scripts\python.exe -c "import PySide6" >nul 2>&1
if errorlevel 1 set "NEEDS_INSTALL=1"

if "!NEEDS_INSTALL!"=="1" (
  .venv\Scripts\python.exe -m pip install --upgrade pip
  if errorlevel 1 goto :bootstrap_error
  .venv\Scripts\python.exe -m pip install -r requirements.txt
  if errorlevel 1 goto :bootstrap_error
  > ".venv\.requirements.sha256" echo !REQUIREMENTS_HASH!
)

> ".venv\.adhelper-ready" echo ready

set "ADHELPER_LOG_DIR=%APPDATA%\ADHelper\logs"
if not exist "%ADHELPER_LOG_DIR%" md "%ADHELPER_LOG_DIR%" >nul 2>&1
set "ADHELPER_LAUNCH_LOG=%ADHELPER_LOG_DIR%\launcher.log"
>> "%ADHELPER_LAUNCH_LOG%" echo [%date% %time%] Запуск ADHelper.

if exist ".venv\Scripts\pythonw.exe" (
  start "" /b ".venv\Scripts\pythonw.exe" main.py %* >> "%ADHELPER_LAUNCH_LOG%" 2>&1
) else (
  .venv\Scripts\python.exe main.py %* >> "%ADHELPER_LAUNCH_LOG%" 2>&1
)
exit /b 0

:bootstrap_error
if exist ".venv\.adhelper-ready" del /q ".venv\.adhelper-ready" >nul 2>&1
echo.
echo Failed to prepare the embedded ADHelper 2 environment.
echo Check Python installation and network access, then run this file again.
pause
exit /b 1
