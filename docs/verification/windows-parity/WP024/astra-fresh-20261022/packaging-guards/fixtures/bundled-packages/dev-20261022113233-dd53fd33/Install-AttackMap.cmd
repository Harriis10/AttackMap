@echo off
setlocal
set "SCRIPT=%~dp0Install-AttackMap.ps1"
where pwsh.exe >nul 2>nul
if %errorlevel%==0 (
  pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
)
set "ATTACKMAP_INSTALL_EXIT=%errorlevel%"
if /I not "%ATTACKMAP_INSTALL_NONINTERACTIVE%"=="1" pause
exit /b %ATTACKMAP_INSTALL_EXIT%
