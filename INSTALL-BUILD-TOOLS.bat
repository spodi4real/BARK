@echo off
setlocal enabledelayedexpansion

REM ===========================================================
REM  BARK - one-time setup helper
REM  Installs the Microsoft C++ Build Tools that Rust needs in
REM  order to produce a Windows program.
REM
REM  Just double-click this file. It asks Windows for permission
REM  by itself.
REM ===========================================================

REM --- Re-launch with administrator rights if we do not have them ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo Asking Windows for administrator permission...
    echo Click YES on the blue box that appears.
    echo.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

title BARK - Installing build tools - do not close

cls
echo ============================================================
echo   BARK
echo   Installing the Microsoft C++ Build Tools
echo ============================================================
echo.
echo   This is a ONE-TIME setup step on this laptop only.
echo   It is NOT needed on the server or on other computers.
echo.
echo   Download size:  about 4 to 7 GB
echo   Time:           10 to 40 minutes
echo.
echo   IMPORTANT
echo   ---------
echo   The screen below will look frozen for a long time.
echo   That is NORMAL. Microsoft's installer works silently.
echo.
echo   Do NOT close this window.
echo   Do NOT press Ctrl+C.
echo.
echo   You can keep using your computer while it runs.
echo.
echo ============================================================
echo.
echo   Starting...
echo.

winget install --id Microsoft.VisualStudio.2022.BuildTools --exact --accept-source-agreements --accept-package-agreements --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

set RC=%errorlevel%

echo.
echo ============================================================
if "%RC%"=="0" (
    echo   FINISHED - the build tools are installed.
    echo.
    echo   Go back to Claude and say:
    echo       build tools finished
) else if "%RC%"=="3010" (
    echo   FINISHED - but Windows wants to restart first.
    echo.
    echo   1. Restart this computer.
    echo   2. Then go back to Claude and say:
    echo          build tools finished
) else if "%RC%"=="-1978335189" (
    echo   ALREADY INSTALLED - nothing to do.
    echo.
    echo   Go back to Claude and say:
    echo       build tools finished
) else (
    echo   SOMETHING WENT WRONG.
    echo   Error code: %RC%
    echo.
    echo   Take a photo or copy the text above this line
    echo   and show it to Claude. Do not worry, it is fixable.
)
echo ============================================================
echo.
echo   Press any key to close this window.
pause >nul
