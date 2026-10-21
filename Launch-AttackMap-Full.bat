@echo off
setlocal
if not "%~2"=="" (
  echo Usage: Launch-AttackMap-Full.bat [full-product build directory]
  exit /b 2
)
if "%~1"=="" (
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0tools\launch_native_full_product.ps1"
) else (
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0tools\launch_native_full_product.ps1" -BuildDirectory "%~1"
)
exit /b %errorlevel%
