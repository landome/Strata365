@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Strata365 Launcher
echo.
echo Strata365
echo ==============================
echo.
echo Checking for PowerShell 7 (pwsh.exe)...
chcp 65001 >nul

where pwsh >nul 2>nul
if errorlevel 1 (
    echo PowerShell 7 ^(pwsh.exe^) not found.
    echo Attempting to install via winget...
    where winget >nul 2>nul
    if errorlevel 1 (
        echo winget not available. Opening download page...
        start "" https://aka.ms/powershell-release?tag=stable
        echo Install PowerShell 7, then re-run this launcher.
        pause
        exit /b 1
    ) else (
        winget install --id Microsoft.Powershell -e --source winget --accept-source-agreements --accept-package-agreements
        if errorlevel 1 (
            echo winget install failed. Opening download page...
            start "" https://aka.ms/powershell-release?tag=stable
            pause
            exit /b 1
        )
    )
)

echo Starting application...
echo.

cd /d "%~dp0"
set "PWSH_EXE=pwsh"
if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" set "PWSH_EXE=%ProgramFiles%\PowerShell\7\pwsh.exe"
if exist "%LocalAppData%\Microsoft\powershell\pwsh.exe" set "PWSH_EXE=%LocalAppData%\Microsoft\powershell\pwsh.exe"
echo Using PowerShell 7: "%PWSH_EXE%"
"%PWSH_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -NoExit -Sta -File "%~dp0GraphApp.ps1"
echo.
echo If the app window did not appear, review any errors above. Leave this window open.

if %errorlevel% neq 0 (
    echo.
    echo Application exited with error code: %errorlevel%
    echo.
    echo Common solutions:
    echo 1. Run Setup.ps1 first to install required modules
    echo 2. Check that you have a Microsoft 365 account
    echo 3. Ensure PowerShell execution policy allows script execution
    echo.
    pause
)
