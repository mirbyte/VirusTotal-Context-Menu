::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Elevate.cmd - Version 4
:: Automatically check & get admin rights
:: Taken from: https://stackoverflow.com/a/12264592
::::::::::::::::::::::::::::::::::::::::::::::::::::::
 @echo off
 CLS
 color 80
 ECHO =============================
 ECHO Running Admin shell
 ECHO =============================
 ECHO.

:init
 setlocal DisableDelayedExpansion
 set cmdInvoke=1
 set winSysFolder=System32
 set "batchPath=%~0"
 for %%k in (%0) do set batchName=%%~nk
 set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
 setlocal EnableDelayedExpansion

:checkPrivileges
  NET FILE 1>NUL 2>NUL
  if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
  if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
  ECHO **************************************
  ECHO Invoking UAC for Privilege Escalation.
  ECHO **************************************
  ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
  ECHO args = "ELEV " >> "%vbsGetPrivileges%"
  ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
  ECHO args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
  ECHO Next >> "%vbsGetPrivileges%"

  if '%cmdInvoke%'=='1' goto InvokeCmd 

  ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
  goto ExecElevation

:InvokeCmd
  ECHO args = "/c """ + "!batchPath!" + """ " + args >> "%vbsGetPrivileges%"
  ECHO UAC.ShellExecute "%SystemRoot%\%winSysFolder%\cmd.exe", args, "", "runas", 1 >> "%vbsGetPrivileges%"

:ExecElevation
 "%SystemRoot%\%winSysFolder%\WScript.exe" "%vbsGetPrivileges%" %*
 exit /B

:gotPrivileges
 setlocal & cd /d %~dp0
 if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

 ::::::::::::::::::::::::::::
 ::START
 ::::::::::::::::::::::::::::
 
 REM github/mirbyte
 REM v1.2
 
 :: UTF8
 chcp 65001 >nul
 title VirusTotal Context Menu Installer v1.2
 setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
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
 rmdir /s /q "%ProgramFiles%\VirusTotalScanner" >nul 2>&1


 :: animation uwu
 echo  +
 powershell -Command "Start-Sleep -Milliseconds 200"
 cls
 echo Removing previous version if exists...
 echo  x
 powershell -Command "Start-Sleep -Milliseconds 200"
 cls
 echo Removing previous version if exists...
 echo  +
 powershell -Command "Start-Sleep -Milliseconds 200"
 cls
 echo Removing previous version if exists...
 echo  x
 powershell -Command "Start-Sleep -Milliseconds 200"
 cls
 echo Removing previous version if exists...
 echo  +
 powershell -Command "Start-Sleep -Milliseconds 200"
 cls
 echo Removing previous version if exists...
 echo  x
 powershell -Command "Start-Sleep -Milliseconds 200"
 cls
 echo Removing previous version if exists...
 echo  +
 powershell -Command "Start-Sleep -Milliseconds 200"
 cls
 echo Removing previous version if exists...
 echo  x
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
 echo|set /p="%api_key%" > "files\api_key.txt"

 cls
 echo Please wait... This might take a minute or two.
 
 type nul > files\api_k.txt
 REM obfuscation 😁
 for /f "delims=" %%A in (files\api_key.txt) do (
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
     echo !Y! >> files\api_k.txt
 )
 cls
 cls
 echo Do you want to install the program to %ProgramFiles%\VirusTotalScanner?
 set /p confirm="Press Y for yes, N for no: "
 cls
 
 if /i "%confirm%"=="Y" (
	 if not exist "%ProgramFiles%\VirusTotalScanner" mkdir "%ProgramFiles%\VirusTotalScanner"
     copy /Y "files\vt_scanner.exe" "%ProgramFiles%\VirusTotalScanner\vt_scanner.exe"
     copy /Y "files\api_k.txt" "%ProgramFiles%\VirusTotalScanner\api_k.txt"
	 echo github.com/mirbyte/VirusTotal-Context-Menu > "%ProgramFiles%\VirusTotalScanner\note.txt"
     reg add "HKEY_CLASSES_ROOT\*\shell\Scan with VirusTotal" /ve /t REG_SZ /d "Scan with VirusTotal" /f
     reg add "HKEY_CLASSES_ROOT\*\shell\Scan with VirusTotal\command" /t REG_SZ /d "\"%ProgramFiles%\\VirusTotalScanner\\vt_scanner.exe\" \"%%1\"" /f
	 
     echo.
     echo Installation completed, please check above for errors.
     echo Press any key to exit...
	 pause >nul
 ) else (
     echo.
     echo Installation cancelled. Edit the script for custom install location.
     echo Press any key to exit...
     pause >nul
 )
 
 