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

chcp 65001 >nul

title VirusTotal Context Menu Installer v1.3

setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

set "INSTDIR=%ProgramFiles%\VirusTotalScanner"
set "SRCDIR=%~dp0bin"

cls

echo ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
echo ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
echo ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
echo ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
echo ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
echo ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
echo ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
echo ████████████████████████████████████████████████████████▒▓▒▒▒▒▒▒▒▓▒▓████████████████████████████████████████████████████
echo ████████████████████████████████████████████████████▓▒░░░░░░░░░░░░░░░▓████▓▓▒▒░░▒███████████████████████████████████████
echo █████████████████████████████████████████████▓▓▓▒▒▒▒▒▒▒▒▒▒▒░▒▒▒▒░░░░░░░▒░  ░░░ ░████████████████████████████████████████
echo ██████████████████████████████████████▒░ ░     ░▒▒▒▒▒░░▓▓▓▓▓▓▓▓██░   ░▒░░░░░░░░▓████████████████████████████████████████
echo ███████████████████████████████████████▓░░░░░░░░░▒▒░░░▓▓▓▒▒▒▒▒▒▓▓▓░   ░▒▒░   ░▓█████████████████████████████████████████
echo █████████████████████████████████████████▒░░░░░▒▒▒░░░▒▒░░░    ░░░▒▒░  ░░▒░░░▒███████████████████████████████████████████
echo ███████████████████████████████████████████▓▒▒▒▓▒░░░▒░░░░    ░░░░░▒▒░  ░░░░░▒███████████████████████████████████████████
echo █████████████████████████████████████████████▓▒▒░░░▒░░░░░░░░░░░▒░░░▒░░░░░░░░░▓██████████████████████████████████████████
echo █████████████████████████████████████████████▒▒▒░░░░░░░▒░░░░░░░░░░░░░ ░ ░░░░░▓██████████████████████████████████████████
echo ████████████████████████████████████████████▒▒▒░░░▒░░░░▒░░░░░░░░░▒░░░░░░░░░░░▒██████████████████████████████████████████
echo ███████████████████████████████████████████▓▒▒▒░░▒░░░░▒░░░░░▒░░░░░░░░░░░ ░░░░░██████████████████████████████████████████
echo ███████████████████████████████████████████▒▒▒░░░▒▒▒▒▒░▒▒░░▒▒░░░░░▒▒▒░░░░░▒▒░░▓█████████████████████████████████████████
echo ██████████████████████████████████████████▒▒▒▒▒░░▒▒▒▓▓▓▓▒▒▒▒▒░░▒▓▓▓▒▒▒░░░░▒▒░░▒█████████████████████████████████████████
echo ██████████github/mirbyte███████████████████▓▒▒░░▒▒▒░▒██▓▒░░░░░░░▒██▒░░░░░▒▒░░░▓█████████████████████████████████████████
echo ██████████████████████████████████████████▓▓▒▒▒░░▒░▒▒░▒▒░░░░░░░░░▒▒░▒░░░░▒▒▒░░░▒████████████████████████████████████████
echo ████████████████████████████████████████████▓▒▓▒▒▒▒▒▓░░░░░░░░░░░░░░▒▒░░░░▒▒▒▒░▒░▓███████████████████████████████████████
echo ████████████████████████████████████████████▓░▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░▒░░░▒▒░▒░▒░▒███████████████████████████████████████
echo █████████████████████████████████████████████▒▒▒▒▓▒▒▒▒▒░░░░░░░░░░░░▒▒░░░░▒▒░░▒▒▒▒███████████████████████████████████████
echo █████████████████████████████████████████████░▒▒▒▓▓▒▒░▒▒▒▒░░░░░░░▒▒▒░░░░░▒▒▒▒▒▒▒░███████████████████████████████████████
echo █████████████████████████████████████████████▓▒▓▓▓▒░░░▒▒▒▓▓▓▓▓▒▒▓▒▓▓░░░░░▒▒▒▒▒▒▒▒▓██████████████████████████████████████
echo ███████████████████████████████████████████▓▒▓████▓▓▓▓▒▒░▒▓▓▓█▓▓▓▓▓▒░░▒░▒▒▓▓▓▓▓▒▒▒██████████████████████████████████████
echo ██████████████████████████████████████████░░░▓███▓▓▓▓▓▓▓░░▓▓▓█▓▓▓▓▓░▒▒▒▒▒▓▓▓▓▓▓▒▒▒▒█████████████████████████████████████
echo █████████████████████████████████████████▓░░▓███▓▓▓▓▓▓█▓▒░▒▓███▓▓▓░░▒▒▓▓▒▓▓▓▓▓▓▓▓▒▒▓████████████████████████████████████
echo ██████████████████████████████████████████▓░▓▓██▓▓█████▓▒▒▒▒▓▓▒▓▓▓▓░▒▓▓▒▓▓▓▓▓▓▓▓▓▒░▒████████████████████████████████████
:: reset characters back
chcp 437 >nul

color 80

timeout /t 3 /nobreak >nul

cls

echo Removing previous version if exists...

reg delete "HKEY_CLASSES_ROOT\*\shell\Scan with VirusTotal" /f >nul 2>&1

rmdir /s /q "!INSTDIR!" >nul 2>&1

:: animation uwu

echo +
powershell -Command "Start-Sleep -Milliseconds 200"
cls
echo Removing previous version if exists...
echo x
powershell -Command "Start-Sleep -Milliseconds 200"
cls
echo Removing previous version if exists...
echo +
powershell -Command "Start-Sleep -Milliseconds 200"
cls
echo Removing previous version if exists...
echo x
powershell -Command "Start-Sleep -Milliseconds 200"
cls
echo Removing previous version if exists...
echo +
powershell -Command "Start-Sleep -Milliseconds 200"
cls
echo Removing previous version if exists...
echo x
powershell -Command "Start-Sleep -Milliseconds 200"
cls
echo Removing previous version if exists...
echo +
powershell -Command "Start-Sleep -Milliseconds 200"
cls
echo Removing previous version if exists...
echo x...
powershell -Command "Start-Sleep -Milliseconds 200"
cls

:: animation end

echo Enter your VirusTotal API key:

set /p api_key=""

cls

if "%api_key%"=="" (
echo Error: API key input was empty.
echo.
echo.
echo Press any key to exit...
pause >nul
exit /b
)

:: FIX SPACES

for /f "delims=" %%a in ("%api_key%") do set api_key=%%a

echo|set /p="%api_key%" > "!SRCDIR!\api_key.txt"

cls

echo Please wait... This might take a minute or two.

type nul > "!SRCDIR!\api_k.txt"

REM obfuscation

for /f "usebackq delims=" %%A in ("!SRCDIR!\api_key.txt") do (
    set "X=%%A"
    set "Y="
    for /l %%B in (0,1,255) do (
        set "Z=!X:~%%B,1!"
        if defined Z (
            for /f "tokens=1 delims==" %%C in ('powershell -command "[int][char]'!Z!'"') do set "A=%%C"
            set /a "B=A+1"
            for /f "tokens=1 delims==" %%D in ('powershell -command "[char]!B!"') do set "F=%%D"
            set "Y=!Y!!F!"
        )
    )
    echo !Y!>> "!SRCDIR!\api_k.txt"
)
del "!SRCDIR!\api_key.txt"

cls

echo Do you want to install the program to !INSTDIR!?

set /p confirm="Press Y for yes, N for no: "

cls

if /i "%confirm%"=="Y" (
echo DEBUG: SRCDIR = !SRCDIR!
echo DEBUG: INSTDIR = !INSTDIR!
echo DEBUG: vt_scanner.exe exists:
if exist "!SRCDIR!\vt_scanner.exe" (echo YES) else (echo NO)
echo DEBUG: api_k.txt exists:
if exist "!SRCDIR!\api_k.txt" (echo YES) else (echo NO)
echo.
if not exist "!INSTDIR!" mkdir "!INSTDIR!"
copy /Y "!SRCDIR!\vt_scanner.exe" "!INSTDIR!\vt_scanner.exe"
copy /Y "!SRCDIR!\api_k.txt" "!INSTDIR!\api_k.txt"
del "!SRCDIR!\api_k.txt"
echo github.com/mirbyte/VirusTotal-Context-Menu > "!INSTDIR!\note.txt"
reg add "HKEY_CLASSES_ROOT\*\shell\Scan with VirusTotal" /ve /t REG_SZ /d "Scan with VirusTotal" /f
reg add "HKEY_CLASSES_ROOT\*\shell\Scan with VirusTotal\command" /t REG_SZ /d "\"!INSTDIR!\vt_scanner.exe\" \"%%1\"" /f
echo.
echo Installation completed, please check above for errors.
echo Press any key to exit...
pause >nul
) else (
del "!SRCDIR!\api_k.txt"
echo.
echo Installation cancelled. Edit the script for custom install location.
echo Press any key to exit...
pause >nul
)
