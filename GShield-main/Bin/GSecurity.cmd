@echo off

:: dht
Reg DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f
Reg DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v SavedLegacySettings /f
Reg DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL /f
Reg DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /f
Reg DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v DefaultConnectionSettings /f
Reg DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxySettingsPerUser /f
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local" /f
bitsadmin /reset /allusers
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer" /f /reg:32
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer" /f /reg:64
Reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
Reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
Reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f
Reg add "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v DisableConfig /t REG_DWORD /d 0 /f
Reg add "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v DisableSR /t REG_DWORD /d 0 /f
Reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /f
Reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend /f /v Start /t REG_DWORD /d 0x00000002
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /f /v DisableAntiSpyware /t REG_DWORD /d 0x00000000
Reg add "HKLM\SYSTEM\CurrentControlSet\services\MpsSvc" /V Start /T REG_DWORD /D 2 /F
Reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /f /v EnableFirewall /t REG_DWORD /d 0x00000001
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /f /v DoNotAllowExceptions
Reg add "HKLM\SYSTEM\CurrentControlSet\services\wuauserv" /V Start /T REG_DWORD /D 2 /F
Reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f /v NoWindowsUpdate
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
Reg add "HKLM\SYSTEM\CurrentControlSet\services\wscsvc" /V Start /T REG_DWORD /D 2 /F
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f /v HideSCAHealth /t REG_SZ /d 0
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f /v HideSCAHealth /t REG_SZ /d 0

:: Autopilot
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Uninstall-ProvisioningPackage -AllInstalledPackages"
rd /s /q %ProgramData%\Microsoft\Provisioning
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverInstall\Restrictions" /v "AllowUserDeviceClasses" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "2" /f

:: Biometrics, Homegroup, and License
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" /v "DisableHomeGroup" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f

:: riddance
for /f "tokens=1,2*" %%x in ('whoami /user /fo list ^| findstr /i "name sid"') do (
    set "USERNAME=%%z"
    set "USERSID=%%y"
)
for /f "tokens=5 delims=-" %%r in ("!USERSID!") do set "RID=%%r"
for /f "tokens=*" %%u in ('net user ^| findstr /i /c:"User" ^| find /v "command completed successfully"') do (
    set "USERLINE=%%u"
    set "USERRID=!USERLINE:~-4!"
    if !USERRID! neq !RID! (
        echo Removing user: !USERLINE!
        net user !USERLINE! /delete
    )
)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f

:: services
sc config FastUserSwitchingCompatibility start= disabled
sc config seclogon start= disabled
sc config LanmanServer start= disabled
sc config LanmanWorkstation start= disabled
sc config TrkWks start= disabled
sc config ALG start= disabled
sc config hkmsvc start= disabled
sc config SharedAccess start= automatic
sc config Netlogon start= disabled
sc config RpcLocator start= disabled
sc config RemoteRegistry start= disabled
sc config RemoteAccess start= disabled
sc config SCardSvr start= disabled
sc config AJRouter start= disabled
sc config PeerDistSvc start= disabled
sc config CertPropSvc start= disabled
sc config NfsClnt start= disabled
sc config dmwappushsvc start= disabled
sc config MapsBroker start= disabled
sc config EntAppSvc start= disabled
sc config fsvc start= disabled
sc config vmickvpexchange start= disabled
sc config vmicguestinterface start= disabled
sc config vmicshutdown start= disabled
sc config vmicheartbeat start= disabled
sc config vmicrdv start= disabled
sc config vmictimesync start= disabled
sc config vmicvmsession start= disabled
sc config vmicvss start= disabled
sc config IEEtwCollectorService start= disabled
sc config iphlpsvc start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config MSiSCSI start= disabled
sc config SmsRouter start= disabled
sc config CscService start= disabled
sc config RetailDemo start= disabled
sc config SensorDataService start= disabled
sc config SensrSvc start= disabled
sc config SensorService start= disabled
sc config ScDeviceEnum start= disabled
sc config SCPolicySvc start= disabled
sc config SNMPTRAP start= disabled
sc config StorSvc start= disabled
sc config TabletInputService start= disabled
sc config WbioSrvc start= disabled
sc config wcncsvc start= disabled
sc config WMPNetworkSvc start= disabled
sc config icssvc start= disabled
sc config Wms start= disabled
sc config WmsRepair start= disabled
sc config WinRM start= disabled
sc config XblAuthManager start= disabled
sc config XblGameSave start= disabled
sc config XboxNetApiSvc start= disabled
sc config Termservice start= disabled

:: threats
reg add "HKLM\Software\Microsoft\Cryptography\Wintrust\Config" /v "EnableCertPaddingCheck" /t REG_SZ /d "1" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /t REG_SZ /d "1" /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "Negotiate" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d "1" /f

:: Script execution
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass}"

REM Remove default user
net user defaultuser0 /delete
net user defaultuser1 /delete
net user defaultuser100000 /delete

REM Perms
for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%d:\ (
        takeown /f %%d:\
        icacls %%d:\ /grant:r "Console Logon":M
        icacls %%d:\ /remove "Everyone"
        icacls %%d:\ /remove "Authenticated Users"
    )
)

for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%d:\ (
        rem Check if the drive is removable
        wmic logicaldisk where "DeviceID='%%d:'" get DriveType 2>nul | find "2" >nul
        if errorlevel 1 (
            rem Check if the drive is formatted with NTFS
            fsutil fsinfo ntfsinfo %%d:\ >nul 2>&1
            if errorlevel 1 (
                echo %%d:\ is not NTFS formatted.
            ) else (
                echo Applying permissions to %%d:\
                takeown /f %%d:\
                icacls %%d:\ /setowner "Administrators"
                icacls %%d:\ /grant:r "Users":RX /T /C
                icacls %%d:\ /grant:r "System":F /T /C
                icacls %%d:\ /grant:r "Administrators":F /T /C
                icacls %%d:\ /grant:r "Authenticated Users":M /T /C
                icacls %%d:\ /grant:r "Console Logon":M
                icacls %%d:\ /remove "Everyone"
                icacls %%d:\ /remove "Authenticated Users"
            )
        ) else (
            echo %%d:\ is not a removable drive.
        )
    )
)

takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:d /T /C
icacls "%SystemDrive%\Users\Public\Desktop" /remove "INTERACTIVE"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "SERVICE"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "BATCH"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "CREATOR OWNER"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "System"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "Administrators"
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:d /T /C
icacls "%USERPROFILE%\Desktop" /remove "System"
icacls "%USERPROFILE%\Desktop" /remove "Administrators"

REM Remove symbolic links
for %%D in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist "%%D:\" (
        for /f "delims=" %%F in ('dir /aL /s /b "%%D:\" 2^>nul') do (
            echo Deleting symbolic link: %%F
            rmdir "%%F" 2>nul || del "%%F" 2>nul
        )
    )
)

REM Loop through all network adapters and apply the DisablePXE setting
for /f "tokens=*" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s /f "Name" /k 2^>nul') do (
    set "adapter=%%A"
    REM Extract the adapter GUID from the registry key path
    set "adapter_guid="
    for /f "tokens=3" %%B in ("!adapter!") do set adapter_guid=%%B

    REM Apply the DisablePXE registry key if the GUID is valid
    if defined adapter_guid (
        echo Setting DisablePXE for adapter: !adapter_guid!
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\!adapter_guid!" /v DisablePXE /t REG_DWORD /d 1 /f
    )
)

for /f "tokens=*" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpipv6\Parameters\Interfaces" /s /f "Name" /k 2^>nul') do (
    set "adapter=%%A"
    REM Extract the adapter GUID from the registry key path
    set "adapter_guid="
    for /f "tokens=3" %%B in ("!adapter!") do set adapter_guid=%%B

    REM Apply the DisablePXE registry key if the GUID is valid
    if defined adapter_guid (
        echo Setting DisablePXE for adapter: !adapter_guid!
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpipv6\Parameters\Interfaces\!adapter_guid!" /v DisablePXE /t REG_DWORD /d 1 /f
    )
)

REM disable netbios
sc config lmhosts start= disabled
@powershell.exe -ExecutionPolicy Bypass -Command "Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object { $_.SetTcpipNetbios(2) }"
wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableNetbios" /t REG_DWORD /d "0" /f
