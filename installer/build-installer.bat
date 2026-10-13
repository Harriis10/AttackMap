@echo off
REM Build the AttackMap Windows app (dist\attackmap\attackmap.exe) with PyInstaller.
setlocal
cd /d "%~dp0\.."

where python >nul 2>nul || (echo Python 3.11+ is required on PATH. & exit /b 1)
python -c "import PyInstaller" 2>nul || python -m pip install "pyinstaller>=6.0"

echo Cleaning previous build...
if exist build\attackmap rmdir /s /q build\attackmap
if exist dist\attackmap rmdir /s /q dist\attackmap

echo Building attackmap.exe (this takes ~3 minutes)...
python -m PyInstaller --noconfirm --onedir --console --name attackmap --paths src ^
  --add-data "src/attackmap/ui/web;attackmap/ui/web" ^
  --add-data "src/attackmap/ui/fixtures;attackmap/ui/fixtures" ^
  --add-data "src/attackmap/taint_sinks.yaml;attackmap" ^
  --hidden-import attackmap.cli --hidden-import attackmap.ui ^
  --hidden-import attackmap.ui.launch --hidden-import attackmap.ui.server ^
  --hidden-import attackmap.ui.runner --hidden-import attackmap.ui.config ^
  --hidden-import attackmap.ui.report --hidden-import attackmap.ui.output ^
  --hidden-import attackmap.ui.secrets --hidden-import attackmap.ui.watch ^
  --hidden-import attackmap.ui.suppress_write ^
  --collect-all attackmap_analyzer_php_web --collect-all attackmap_analyzer_python ^
  --collect-all attackmap_analyzer_node_service --collect-all attackmap_analyzer_iac ^
  --collect-all attackmap_analyzer_rust --collect-all attackmap_analyzer_go ^
  --collect-all attackmap_analyzer_java_spring --collect-all attackmap_analyzer_dotnet ^
  --collect-all attackmap_analyzer_terraform --collect-all attackmap_analyzer_c ^
  --collect-all attackmap_analyzer_cpp --collect-all attackmap_analyzer_swift ^
  --collect-all attackmap_analyzer_atproto --collect-all attackmap_analyzer_php_laminas ^
  --collect-all attackmap_analyzer_omeka_s ^
  --exclude-module matplotlib --exclude-module numpy ^
  --exclude-module pandas --exclude-module scipy --exclude-module PIL ^
  --exclude-module pytest --exclude-module IPython ^
  installer\entry.py
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
