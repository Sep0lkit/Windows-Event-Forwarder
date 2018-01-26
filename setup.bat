@echo off

echo ------------------------------------------------------
echo Windows Event Forwarder -- Centralizing Windows Logs
echo [ WinEvt, Sysmon, Powershell ]
echo Build Date:	2018-01-17 
echo Bug Reporting: 	sep0lkit@gmail.com
echo.
echo ------------------------------------------------------


::Configure
set LogServer=127.0.0.1
set port=514


::Variables
if  EXIST "%PROGRAMFILES(x86)%" (
	::64bit
	set nxlog_root="%PROGRAMFILES(x86)%\nxlog"
	set nxlog_backup="%PROGRAMFILES(x86)%\nxlog\backup"
	set os_arch="x64"
) ELSE (
	::32bit
	set nxlog_root="%PROGRAMFILES%\nxlog"
	set nxlog_backup="%PROGRAMFILES(x86)%\nxlog\backup"
	set os_arch="x86"
)
::backup folder
mkdir %nxlog_root%\backup	>nul 2>nul


::OS Version
:: 2003 ==> 5.x 2008 ==> 6.x 2012 => 6.x	Win10 => 10.x
:: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx 
ver |findstr "5\.[0-2]\.*  6\.[0-3]\.* 10\.[0-1]\.*" > NUL
if  errorlevel 1 ( 
	echo  Windows Event Forwarder 
	echo  Not supported, In most case is low system version
	pause
	exit
)

::Windows Event size
ver |findstr "6\.[0-3]\.* 10\.[0-1]\.*" > NUL
if not errorlevel 1 (
	echo -Setting Windows Evnet Size...
	::Security: 200M System: 100M Application: 100M
	wevtutil sl Security  /q /rt:false  /ab:false /ms:209715200
	wevtutil sl System  /q /rt:false  /ab:false /ms:104857600
	wevtutil sl Application  /q /rt:false  /ab:false /ms:104857600
) else (
	echo -Setting Windows Evnet Size...
	rem Security
	reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Security /v MaxSize /t REG_DWORD /d 0xc800000 /f >nul
	reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Security /v Retention /t REG_DWORD /d 0x0 /f >nul
	reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Security /v Retention /t REG_DWORD /d 0x0 /f >nul

	rem System
	reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\System /v MaxSize /t REG_DWORD /d 0x1000000 /f >nul
	reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\System /v Retention /t REG_DWORD /d 0x0 /f >nul
	reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\System /v Retention /t REG_DWORD /d 0x0 /f >nul

	rem Application
	reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Application /v MaxSize /t REG_DWORD /d 0x1000000 /f >nul
	reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Application /v Retention /t REG_DWORD /d 0x0 /f >nul
	reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Application /v Retention /t REG_DWORD /d 0x0 /f >nul
)
echo -Windows Event completed [ Security: 200M System: 100M Application: 100M ]
echo.

::Advanced audit policy
ver |findstr "6\.[0-3]\.* 10\.[0-1]\.*" > NUL
if not errorlevel 1 ( 
	echo -Setting advanced audit policy
	rem System
	rem "Security System Extension"
	auditpol.exe /set /subcategory:{0cce9211-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "System Integrity"
	auditpol.exe /set /subcategory:{0cce9212-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "IPsec Driver"
	auditpol.exe /set /subcategory:{0cce9213-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Other System Events"
	auditpol.exe /set /subcategory:{0cce9214-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Security State Change"
	auditpol.exe /set /subcategory:{0cce9210-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem Logon/Logoff
	rem "Logon"
	auditpol.exe /set /subcategory:{0cce9215-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Logoff"
	auditpol.exe /set /subcategory:{0cce9216-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Account Lockout"
	auditpol.exe /set /subcategory:{0cce9217-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "IPsec Main Mode"
	auditpol.exe /set /subcategory:{0cce9218-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "IPsec Quick Mode"
	auditpol.exe /set /subcategory:{0cce9219-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "IPsec Extended Mode"
	auditpol.exe /set /subcategory:{0cce921a-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Special Logon"
	auditpol.exe /set /subcategory:{0cce921b-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Other Logon/Logoff Events"
	auditpol.exe /set /subcategory:{0cce921c-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Network Policy Server"
	auditpol.exe /set /subcategory:{0cce9243-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem Object Access
	rem "File System"
	auditpol.exe /set /subcategory:{0cce921d-69ae-11d9-bed3-505054503030} /failure:disable /success:disable >nul 2>nul
	rem "Registry"
	auditpol.exe /set /subcategory:{0cce921e-69ae-11d9-bed3-505054503030} /failure:disable /success:disable >nul 2>nul
	rem "Kernel Object"
	auditpol.exe /set /subcategory:{0cce921f-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "SAM"
	auditpol.exe /set /subcategory:{0cce9220-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Certification Services"
	auditpol.exe /set /subcategory:{0cce9221-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Application Generated"
	auditpol.exe /set /subcategory:{0cce9222-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Handle Manipulation"
	auditpol.exe /set /subcategory:{0cce9223-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "File Share"
	auditpol.exe /set /subcategory:{0cce9224-69ae-11d9-bed3-505054503030} /failure:enable /success:disable >nul 2>nul
	rem "Filtering Platform Packet Drop"
	auditpol.exe /set /subcategory:{0cce9225-69ae-11d9-bed3-505054503030} /failure:disable /success:disable >nul 2>nul
	rem "Filtering Platform Connection"
	auditpol.exe /set /subcategory:{0cce9226-69ae-11d9-bed3-505054503030} /failure:disable /success:disable >nul 2>nul
	rem "Other Object Access Events"
	auditpol.exe /set /subcategory:{0cce9227-69ae-11d9-bed3-505054503030} /failure:disable /success:disable >nul 2>nul
	rem "Detailed File Share"
	auditpol.exe /set /subcategory:{0cce9244-69ae-11d9-bed3-505054503030} /failure:enable /success:disable >nul 2>nul
	rem "Removable storage"
	auditpol.exe /set /subcategory:{0CCE9245-69AE-11D9-BED3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem Privilege Use
	rem "Sensitive Privilege Use"
	auditpol.exe /set /subcategory:{0cce9228-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Non Sensitive Privilege Use"
	auditpol.exe /set /subcategory:{0cce9229-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Other Privilege Use Events"
	auditpol.exe /set /subcategory:{0cce922a-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem Detailed Tracking
	rem "Process Termination"
	auditpol.exe /set /subcategory:{0cce922c-69ae-11d9-bed3-505054503030} /failure:disable /success:disable >nul 2>nul
	rem "DPAPI Activity"
	auditpol.exe /set /subcategory:{0cce922d-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "RPC Events"
	auditpol.exe /set /subcategory:{0cce922e-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Process Creation"
	auditpol.exe /set /subcategory:{0cce922b-69ae-11d9-bed3-505054503030} /failure:disable /success:disable >nul 2>nul
	rem Policy Change
	rem "Audit Policy Change"
	auditpol.exe /set /subcategory:{0cce922f-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Authentication Policy Change"
	auditpol.exe /set /subcategory:{0cce9230-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Authorization Policy Change"
	auditpol.exe /set /subcategory:{0cce9231-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "MPSSVC Rule-Level Policy Change"
	auditpol.exe /set /subcategory:{0cce9232-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Filtering Platform Policy Change"
	auditpol.exe /set /subcategory:{0cce9233-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Other Policy Change Events"
	auditpol.exe /set /subcategory:{0cce9234-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem Account Management
	rem "User Account Management"
	auditpol.exe /set /subcategory:{0cce9235-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Computer Account Management"
	auditpol.exe /set /subcategory:{0cce9236-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Security Group Management"
	auditpol.exe /set /subcategory:{0cce9237-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Distribution Group Management"
	auditpol.exe /set /subcategory:{0cce9238-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Application Group Management"
	auditpol.exe /set /subcategory:{0cce9239-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Other Account Management Events"
	auditpol.exe /set /subcategory:{0cce923a-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem DS Access
	rem "Directory Service Changes"
	auditpol.exe /set /subcategory:{0cce923c-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Directory Service Replication"
	auditpol.exe /set /subcategory:{0cce923d-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Detailed Directory Service Replication"
	auditpol.exe /set /subcategory:{0cce923e-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Directory Service Access"
	auditpol.exe /set /subcategory:{0cce923b-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem Account Logon
	rem "Kerberos Service Ticket Operations"
	auditpol.exe /set /subcategory:{0cce9240-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Other Account Logon Events"
	auditpol.exe /set /subcategory:{0cce9241-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Kerberos Authentication Service"
	auditpol.exe /set /subcategory:{0cce9242-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul
	rem "Credential Validation"
	auditpol.exe /set /subcategory:{0cce923f-69ae-11d9-bed3-505054503030} /failure:enable /success:enable >nul 2>nul

	rem Force audit policy subcategory settings
	reg add HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ /v scenoapplylegacyauditpolicy /t REG_DWORD /d 0x00000001 /f >nul 2>nul
	rem backup 
	copy /Y "%systemroot%\system32\grouppolicy\machine\microsoft\windows nt\audit\audit.csv" %nxlog_backup%\audit_backup.csv >nul 2>nul
	rem import audit policy
	if  exist %nxlog_backup%\audit_export.csv ( del /F %nxlog_backup%\audit_export.csv >nul 2>nul)
	auditpol /backup /file:%nxlog_backup%\audit_export.csv  >nul 2>nul
	copy /Y %nxlog_backup%\audit_export.csv "%systemroot%\system32\grouppolicy\machine\microsoft\windows nt\audit\audit.csv" >nul 2>nul
	set audit_status="Advanced audit"
) else ( 
	echo -Advanced audit policy is not supported on this server
	echo -Setting basic audit policy
	rem Todo: basic audit policy
	if  exist %nxlog_backup%\audit_basic.txt ( del /F %nxlog_backup%\audit_basic.txt >nul 2>nul)
	secedit /export /cfg %nxlog_backup%\audit_basic.txt /quiet 
	echo AuditDSAccess=3            >>%nxlog_backup%\audit_basic.txt
	echo AuditLogonEvents=3			>>%nxlog_backup%\audit_basic.txt
	echo AuditSystemEvents=3        >>%nxlog_backup%\audit_basic.txt
	echo AuditObjectAccess=0		>>%nxlog_backup%\audit_basic.txt
	echo AuditPrivilegeUse=3		>>%nxlog_backup%\audit_basic.txt
	echo AuditPolicyChange=3		>>%nxlog_backup%\audit_basic.txt
	echo AuditAccountLogon=3		>>%nxlog_backup%\audit_basic.txt
	echo AuditAccountManage=3		>>%nxlog_backup%\audit_basic.txt
	echo AuditProcessTracking=3		>>%nxlog_backup%\audit_basic.txt

	secedit /configure /db %nxlog_backup%\auditpolicy.sdb /cfg %nxlog_backup%\audit_basic.txt  /quiet
	set audit_status="Basic audit"
)
echo -audit policy completed
echo.

::Sysmon setup and sysmon logging
ver |findstr "6\.[1-3]\.* 10\.[0-1]\.*" > nul
if not errorlevel 1 ( 
	echo -Setting sysmon audit
	copy /Y sysmon.xml %nxlog_backup%\sysmon.xml >nul 
	sc query state= all |find /i "sysmon" >nul 
	if not errorlevel 1 (
		echo -Found sysmon service
		echo -Update sysmon config
		rem Todo: Update sysmon config
		if exist "%windir%\sysmon.exe" ( %windir%\sysmon.exe -c %nxlog_backup%\sysmon.xml >nul 2>nul) 
		if exist "%windir%\sysmon64.exe" ( %windir%\sysmon64.exe -c %nxlog_backup%\sysmon.xml >nul 2>nul)
		echo -Updated sysmon config
	) else (
		echo -Installing sysmon...
		if %os_arch% == "x86" (
			start /wait sysmon.exe /accepteula -i %nxlog_backup%\sysmon.xml
			net start sysmon >nul 2>nul
		) else (
			start /wait sysmon64.exe /accepteula -i %nxlog_backup%\sysmon.xml
			net start sysmon64 >nul 2>nul
		)
	)
	set sysmon_status="Enabled"
	echo -Sysmon setting completed
) else (
	echo -Sysmon is not supported on this server
)
echo.

::Powershell logging
ver |findstr "6\.[1-3]\.* 10\.[0-1]\.*" > NUL
if not errorlevel 1 ( 
	echo -Setting Powershell audit
	:: Powershell module logging
	reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /t REG_DWORD /d 0x00000001 /f >nul 2>nul
	reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames /v * /t REG_SZ /d * /f >nul 2>nul

	:: Powershell script block logging
	reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 0x00000001 /f  >nul 2>nul

	set powershell_status="Enabled"
	echo -Powershell audit policy completed
) else (
	echo -Powershell audit is not supported on this server
)
echo.

::Nxlog logging
echo -Setting nxlog 
sc query state= all |find /i "nxlog" >nul 2>nul
if not errorlevel 1 (
	echo -Found nxlog service
) else (
	echo -Installing nxlog...
	start /wait nxlog-ce-2.9.1716.msi /quiet /passive /norestart
)


if  EXIST "%nxlog_root%\nxlog_tpl.conf" (
	del /F %nxlog_root%\nxlog_tpl.conf >nul 2>nul
)

echo -Generate nxlog conf
echo ## This is a sample configuration file. See the nxlog reference manual about the		>>%nxlog_root%\nxlog_tpl.conf
echo ## configuration options. It should be installed locally and is also available			>>%nxlog_root%\nxlog_tpl.conf
echo ## online at http://nxlog.org/nxlog-docs/en/nxlog-reference-manual.html				>>%nxlog_root%\nxlog_tpl.conf
echo. 																						>>%nxlog_root%\nxlog_tpl.conf
echo ## Please set the ROOT to the folder your nxlog was installed into,					>>%nxlog_root%\nxlog_tpl.conf
echo ## otherwise it will not start.														>>%nxlog_root%\nxlog_tpl.conf
echo. 																						>>%nxlog_root%\nxlog_tpl.conf
echo define ROOT %nxlog_root:"=%   															>>%nxlog_root%\nxlog_tpl.conf
echo. 																						>>%nxlog_root%\nxlog_tpl.conf
echo Moduledir %%ROOT%%\modules 															>>%nxlog_root%\nxlog_tpl.conf
echo CacheDir %%ROOT%%\data																	>>%nxlog_root%\nxlog_tpl.conf
echo Pidfile %%ROOT%%\data\nxlog.pid														>>%nxlog_root%\nxlog_tpl.conf
echo SpoolDir %%ROOT%%\data																	>>%nxlog_root%\nxlog_tpl.conf
echo LogFile %%ROOT%%\data\nxlog.log 														>>%nxlog_root%\nxlog_tpl.conf
echo. 																						>>%nxlog_root%\nxlog_tpl.conf
echo. 																						>>%nxlog_root%\nxlog_tpl.conf
echo ^<Extension json^>																		>>%nxlog_root%\nxlog_tpl.conf
echo     Module xm_json																		>>%nxlog_root%\nxlog_tpl.conf
echo ^</Extension^>																			>>%nxlog_root%\nxlog_tpl.conf
echo. 																						>>%nxlog_root%\nxlog_tpl.conf
echo. 																						>>%nxlog_root%\nxlog_tpl.conf

ver |findstr "5\.[0-2]\.*" > NUL && (goto Winevt-2003)

:Winevt-2008
rem Windows 2008 and above eventlog input
echo ^<Input in^> 																			>>%nxlog_root%\nxlog_tpl.conf
echo     Module      im_msvistalog 															>>%nxlog_root%\nxlog_tpl.conf
echo 	^<QueryXML^>																		>>%nxlog_root%\nxlog_tpl.conf
echo        ^<QueryList^>																	>>%nxlog_root%\nxlog_tpl.conf
echo            ^<Query Id="0"^>															>>%nxlog_root%\nxlog_tpl.conf
echo				^<Select Path="Application"^>*^</Select^>								>>%nxlog_root%\nxlog_tpl.conf
echo				^<Select Path="System"^>*^</Select^>									>>%nxlog_root%\nxlog_tpl.conf
echo				^<Select Path="Security"^>*^</Select^>									>>%nxlog_root%\nxlog_tpl.conf
rem sysmon features, supported: Windows 7 - Windows Server 2008 R2 and higher
wevtutil el |find /i "Microsoft-Windows-Sysmon/Operationa" >nul 2>nul
if not errorlevel 1 (
echo				^<Select Path="Microsoft-Windows-Sysmon/Operational"^>*^</Select^>		>>%nxlog_root%\nxlog_tpl.conf
)
wevtutil el |find /i "Microsoft-Windows-PowerShell/Operational" >nul 2>nul
if not errorlevel 1 (
echo				^<Select Path="Microsoft-Windows-PowerShell/Operational"^>*^</Select^>	>>%nxlog_root%\nxlog_tpl.conf	
)
echo            ^</Query^>																	>>%nxlog_root%\nxlog_tpl.conf
echo        ^</QueryList^>																	>>%nxlog_root%\nxlog_tpl.conf
echo    ^</QueryXML^>																		>>%nxlog_root%\nxlog_tpl.conf
echo    Exec to_json(); 																	>>%nxlog_root%\nxlog_tpl.conf
echo ^</Input^> 																			>>%nxlog_root%\nxlog_tpl.conf

goto end-input


rem Windows 2003 and earlier eventlog input
:Winevt-2003
echo ^<Input in^>																			>>%nxlog_root%\nxlog_tpl.conf
echo  	Module      im_mseventlog															>>%nxlog_root%\nxlog_tpl.conf
echo   	Exec to_json(); 																	>>%nxlog_root%\nxlog_tpl.conf
echo ^</Input^> 																			>>%nxlog_root%\nxlog_tpl.conf
goto end-input

:end-input
echo. 																						>>%nxlog_root%\nxlog_tpl.conf
echo. 																						>>%nxlog_root%\nxlog_tpl.conf
echo ^<Extension charconv^>																	>>%nxlog_root%\nxlog_tpl.conf
echo     Module	xm_charconv																	>>%nxlog_root%\nxlog_tpl.conf
echo     AutodetectCharsets utf-8, utf-16, utf-32, iso8859-2								>>%nxlog_root%\nxlog_tpl.conf
echo ^</Extension^>																			>>%nxlog_root%\nxlog_tpl.conf
echo. 																						>>%nxlog_root%\nxlog_tpl.conf
echo. 																						>>%nxlog_root%\nxlog_tpl.conf
echo ^<Output out^>																			>>%nxlog_root%\nxlog_tpl.conf
echo    Module      om_udp																	>>%nxlog_root%\nxlog_tpl.conf
echo    Host        %LogServer%																>>%nxlog_root%\nxlog_tpl.conf
echo    Port        %port%																	>>%nxlog_root%\nxlog_tpl.conf
echo ^</Output^>																			>>%nxlog_root%\nxlog_tpl.conf
echo. 																						>>%nxlog_root%\nxlog_tpl.conf
echo ^<Route 1^>																			>>%nxlog_root%\nxlog_tpl.conf
echo    Path        in =^> out 																>>%nxlog_root%\nxlog_tpl.conf                     	
echo ^</Route^>																				>>%nxlog_root%\nxlog_tpl.conf

copy /Y %nxlog_root%\nxlog_tpl.conf %nxlog_root%\conf\nxlog.conf >nul 2>nul
echo -Restarting nxlog
net stop nxlog  > nul 2>nul
net start nxlog > nul 2>nul
sc query |find /i "nxlog" >nul 2>nul
if not errorlevel 1 ( set nxlog_status="Enabled" )
echo -Nxlog setting completed

::Reporting 
echo.
echo -Windows Event Forwarder install completed!

echo -Website: https://github.com/Sep0lkit/Windows-Event-Forwarder
echo.
echo Current Setting:
echo  -  LogServer:				%LogServer%:%port%
echo  -  Nxlog: 				%nxlog_status% 	
echo  -  Audit Policy:			%audit_status%
echo  -  Sysmon:				%sysmon_status%
echo  -  Powershell:				%powershell_status%
rem wait
ping 127.0.0.1 -n 10 > nul
