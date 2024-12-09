::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Elevate.cmd - Version 4
:: Automatically check & get admin rights
:: Taken from: https://stackoverflow.com/a/12264592
::::::::::::::::::::::::::::::::::::::::::::::::::::::
 @echo off
 CLS
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
  ECHO.
  ECHO **************************************
  ECHO Invoking UAC for Privilege Escalation
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
 cls
 echo Enter your VirusTotal API key:
 set /p api_key=""
 :: FIX SPACES
 for /f "delims=" %%a in ("%api_key%") do set api_key=%%a
 echo|set /p="%api_key%" > "files\api_key.txt"

 cls
 echo Do you want to install the program to %ProgramFiles%\VirusTotalScanner?
 set /p confirm="Press Y for Yes, N for No: "
 cls
 if /i "%confirm%"=="Y" (
	 if not exist "%ProgramFiles%\VirusTotalScanner" mkdir "%ProgramFiles%\VirusTotalScanner"
     copy /Y "files\vt_scanner.exe" "%ProgramFiles%\VirusTotalScanner\vt_scanner.exe"
     copy /Y "files\api_key.txt" "%ProgramFiles%\VirusTotalScanner\api_key.txt"
	 
     reg add "HKEY_CLASSES_ROOT\*\shell\Scan with VirusTotal" /ve /t REG_SZ /d "Scan with VirusTotal" /f
     reg add "HKEY_CLASSES_ROOT\*\shell\Scan with VirusTotal\command" /t REG_SZ /d "\"%ProgramFiles%\\VirusTotalScanner\\vt_scanner.exe\" \"%%1\"" /f
	 
     echo.
     echo.
     echo Installation completed.
     pause
 ) else (
     echo.
     echo Installation cancelled. Please edit the script for custom install location.
     echo.
     echo.
     pause
     exit /b
 )
 
 
