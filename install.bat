@echo off

setlocal ENABLEEXTENSIONS

set PWD=%~dp0
set BuildDir=Debug

NET SESSION >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    ECHO Administrator PRIVILEGES Detected
) ELSE (
    ECHO please run this bat file in Administrator privileges
	goto EXIT
)

:NextArg

if "%1" == "/debug" 	(set BuildDir=Debug)
if "%1" == "/release" 	(set BuildDir=Release)

if "%1" == "" goto ArgOk

goto NextArg

:ArgOk

IF "%PROCESSOR_ARCHITECTURE%" == "AMD64" goto ARCH_AMD64
IF "%PROCESSOR_ARCHITECTURE%" == "x86" goto ARCH_X86

echo "can't match PROCESSOR_ARCHITECTURE value %PROCESSOR_ARCHITECTURE%"
goto EXIT

:ARCH_AMD64
SET ArchDir=x64
goto StartInstall

:ARCH_X86
SET ArchDir=Win32
goto StartInstall

goto EXIT

:StartInstall
copy /Y "%PWD%%ArchDir%\%BuildDir%\Driver\dokan1.sys" "%SystemRoot%\system32\drivers"
copy /Y "%PWD%%ArchDir%\%BuildDir%\dokan1.dll" "%SystemRoot%\system32"
copy /Y "%PWD%%ArchDir%\%BuildDir%\dokannp1.dll" "%SystemRoot%\system32"

cd /d "%PWD%%ArchDir%\%BuildDir%"

echo installing dokany driver ...
dokanctl.exe /i d

echo installing dokany network provider ...
dokanctl.exe /i n

cd /d "%PWD%"

goto EXIT

:USAGE
echo "%0 [/debug] [/release]"
goto EXIT

:EXIT

