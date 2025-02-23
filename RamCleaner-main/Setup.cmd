@echo off
Title GShield && Color 0b

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Move to the script directory
cd /d %~dp0

:: Step 3: Move to the 'Bin' subfolder
cd Bin

:: Step 4: Install RamCleaner
cd RamCleaner
mkdir C:\Windows\RamCleaner
copy /y emptystandbylist.exe C:\Windows\RamCleaner\emptystandbylist.exe
copy /y RamCleaner.bat C:\Windows\RamCleaner\RamCleaner.bat
schtasks /create /tn "RamCleaner" /xml StartRamCleanerOnLogon.xml /ru "SYSTEM"
