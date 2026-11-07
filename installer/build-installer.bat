@echo off
REM Build the AttackMap Windows app (dist\attackmap\attackmap.exe) with PyInstaller.
REM The authoritative build definition is installer\attackmap.spec; this wrapper
REM only ensures the environment, cleans stale outputs, and delegates to it.
setlocal
set "ROOTDIR=%~dp0\.."
cd /d "%ROOTDIR%"

where python >nul 2>nul || (echo Python 3.11+ is required on PATH. & exit /b 1)
python -c "import PyInstaller" 2>nul || python -m pip install "pyinstaller>=6.0"

echo Cleaning previous build...
if exist build\attackmap rmdir /s /q build\attackmap
if exist dist\attackmap rmdir /s /q dist\attackmap

echo Building attackmap.exe (this takes ~3 minutes)...
python -m PyInstaller --noconfirm installer\attackmap.spec
if errorlevel 1 exit /b 1

if not exist dist\attackmap\attackmap.exe (echo Build failed: dist\attackmap\attackmap.exe not found. & exit /b 1)

echo.
echo Built: %CD%\dist\attackmap\attackmap.exe
echo.
echo Run the GUI with:   dist\attackmap\attackmap.exe ui
echo Analyze a repo:    dist\attackmap\attackmap.exe analyze C:\path\to\repo
echo.
echo To install system-wide, copy the whole dist\attackmap folder to a folder on
echo your PATH (e.g. %%LOCALAPPDATA%%\Programs\AttackMap) and run:  attackmap.exe ui
endlocal
