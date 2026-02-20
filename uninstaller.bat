@echo off
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Run this script as administrator.
    echo Right-click the file and select "Run as administrator".
    echo.
    pause >nul
    exit /b
)

REM github/mirbyte
REM v1.1

color 80
title VTCM Uninstaller (mirbyte)
setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
cls

reg delete "HKEY_CLASSES_ROOT\*\shell\Scan with VirusTotal" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo Registry entry removed successfully.
) else (
    echo No previous registry entry found.
)

if exist "%ProgramFiles%\VirusTotalScanner" (
    powershell -Command "Remove-Item -Path '%ProgramFiles%\VirusTotalScanner' -Recurse -Force"
    if exist "%ProgramFiles%\VirusTotalScanner" (
        echo Failed to remove program files. Try closing any programs that may be using them.
    ) else (
        echo Program files removed successfully.
    )
) else (
    echo No previous installation found.
)

echo.
echo Done :3
echo Press any key to exit...
pause >nul
