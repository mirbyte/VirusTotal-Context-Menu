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
 REM first version of uninstaller
 
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
 rmdir /s /q "%ProgramFiles%\VirusTotalScanner" >nul 2>&1
 if %errorlevel% equ 0 (
     echo Program files removed successfully.
 ) else (
     echo No previous installation found.
 )
 echo.
 echo Done :3
 echo Press any key to exit...
 pause >nul
 
 
 

 
 