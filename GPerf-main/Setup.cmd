@echo off
Title GPerf && Color 0b

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Move to the script directory
cd /d %~dp0

:: Step 3: Working folder
cd Bin

:: Step 4: Initialize environment 
setlocal EnableExtensions DisableDelayedExpansion

:: Step 7: Execute CMD (.cmd) files alphabetically
call GPerf.cmd

:: Step 8: Execute Registry (.reg) files
reg import GPerf.reg
