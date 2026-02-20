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

color 80
title VTCM Uninstaller (mirbyte)
setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

cls

set "REG_HKLM=HKLM\SOFTWARE\Classes\*\shell\Scan with VirusTotal"
set "REG_HKCU=HKCU\Software\Classes\*\shell\Scan with VirusTotal"
set "INSTDIR=%ProgramFiles%\VirusTotalScanner"

set "reg_removed=0"

reg delete "%REG_HKLM%" /f >nul 2>&1
if %errorlevel% equ 0 set "reg_removed=1"

reg delete "%REG_HKCU%" /f >nul 2>&1
if %errorlevel% equ 0 set "reg_removed=1"

if "%reg_removed%"=="1" (
echo Registry entry removed successfully.
) else (
echo No previous registry entry found.
)

if exist "%INSTDIR%" (
powershell -Command "Remove-Item -Path '%INSTDIR%' -Recurse -Force"
if exist "%INSTDIR%" (
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
