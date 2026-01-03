# Threat-Hunting-Project-Azuki Breach
<img width="574" height="374" alt="image" src="https://github.com/user-attachments/assets/5bc73787-6e91-428c-bc15-87c17f4f755e" />

# Section 1 – Investigation Summary & Attacker Analysis




## Executive Summary
Between **2025-11-19** and **2025-12-05**, an attacker conducted a sustained intrusion against multiple azuki systems using compromised credentials. The attacker harvested administrative credentials, staged sensitive data, established persistence, and exfiltrated compressed archives to external cloud services. Defensive controls were deliberately weakened to maintain stealth and ensure uninterrupted access. The total dwell time was **16 days**, indicating a controlled post-exploitation campaign rather than opportunistic activity.

**Impact Level:** High  
**Status:** Contained (no active persistence detected)

---

## Timeline
- **Attack Start:** 2025-11-19 UTC  
- **Attack End:** 2025-12-05 UTC  
- **Detection Time:** 2025-12-05 UTC  
- **Duration:** 16 days  

---

## Attacker Progression (Kill Chain)

### 1. Initial Access
- **Method:** Valid credential abuse  
- **Account:** `kenji.sato`  
- The attacker bypassed perimeter defenses by authenticating with legitimate credentials, avoiding exploit-based detection.

---

### 2. Execution
- **Tools:** PowerShell, native Windows utilities  
- **Files:** `svchost.ps1`, `wupdate.ps1`, `pd.exe`  
- Execution relied on living-off-the-land techniques to blend into normal administrative behavior.

---

### 3. Credential Access
- **Tool:** `pd.exe`  
- Administrative credentials were harvested to enable lateral movement and privilege expansion.

---

### 4. Persistence
- **Mechanisms:**
  - Scheduled task masquerading as `svchost.exe`
  - Hidden PowerShell scripts in `ProgramData` and system directories
- **Purpose:** Maintain access across reboots while avoiding user suspicion.

---

### 5. Defense Evasion
- Windows Defender exclusions configured  
- Event logs cleared using `wevtutil.exe`  
- Files marked hidden using `attrib.exe`  

These actions reduced endpoint visibility and delayed detection.

---

### 6. Lateral Movement
- **Technique:** RDP  
- **Accounts Used:** `yuki.tanaka`, `fileadmin`  
- **Target System:** `azuki-fileserver01`  

Lateral movement occurred without brute-force activity, relying on harvested credentials.

---

### 7. Collection & Staging
- **Staging Directories:**
  - `C:\Windows\Logs\CBS`
  - `C:\ProgramData\WindowsCache`
- **Archives:**
  - `credentials.tar.gz`
  - `export-data.zip`
- Sensitive administrative data was staged locally prior to exfiltration.

---

### 8. Command and Control (C2)
- **C2 Server:** `78.141.196.6`  
- **Protocol:** HTTPS  

C2 infrastructure enabled remote command execution, persistence management, and coordinated exfiltration while blending into normal encrypted web traffic.

---

### 9. Exfiltration
- **Destinations:** `file.io`, Discord  
- **Method:** HTTPS uploads of compressed archives  

Public cloud services were used to bypass reputation-based filtering and egress controls.

---

## What the Attacker Gained
- Administrative credentials  
- Access to internal file shares  
- Long-term system access via persistence  
- Lateral movement capability across systems  
- Confirmed exfiltration of sensitive administrative data  

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|------|---------|
| Initial Access | T1078 – Valid Accounts |
| Execution | T1059.001 – PowerShell |
| Credential Access | T1003 – OS Credential Dumping |
| Persistence | T1053.005 – Scheduled Task |
| Defense Evasion | T1562.001 – Disable or Modify Tools |
| Lateral Movement | T1021.001 – Remote Services (RDP) |
| Collection | T1005 – Data from Local System |
| Exfiltration | T1041 – Exfiltration Over C2 Channel |
| Command and Control | T1071.001 – Web Protocols |

---

## Attacker Map (High-Level Flow)
1. Valid credentials used for initial access  
2. Credential dumping to expand access  
3. Persistence established via scheduled tasks and hidden scripts  
4. Defender exclusions and log tampering applied  
5. Lateral movement via RDP  
6. Data staged in hidden directories  
7. C2 communication established  
8. Data exfiltrated via HTTPS  

---

## Why C2 Malware Is Used for Data Exfiltration
C2 malware provides encrypted, reliable, and controllable communication between attacker and victim systems. It enables staged uploads, command execution, retry logic, and adaptive behavior while blending into legitimate HTTPS traffic. This supports long-term access rather than one-time theft.

---

## Why These Techniques Were Chosen
- **Valid accounts:** Avoid exploit-based detection  
- **PowerShell & LOLBins:** Blend into administrative activity  
- **Scheduled tasks:** Persistent access without services or drivers  
- **Defender exclusions:** Remove endpoint visibility  
- **Log clearing:** Delay forensic analysis  
- **Cloud exfiltration:** Evade perimeter-based controls  

The attacker prioritized stealth, persistence, and operational control.

---

## Key Indicators of Compromise (IOCs)

**Source IPs:**  
- `88.97.178.12`  
- `159.26.106.98`  

**C2 Server:**  
- `78.141.196.6`  

**Compromised Accounts:**  
- `kenji.sato`  
- `yuki.tanaka`  
- `fileadmin`  

**Malicious Files:**  
- `pd.exe`  
- `mm.exe`  
- `svchost.ps1`  
- `wupdate.ps1`  

**Persistence Mechanism:**  
- Scheduled task masquerading as `svchost.exe` in `ProgramData`

**Exfiltration Destinations:**  
- `file.io`  
- Discord

# Section 2 – Detection & Threat Hunting Queries (Initial 10)

This section documents the first set of Microsoft Sentinel / Defender Advanced Hunting queries used during the investigation. Each query is presented with its purpose, investigative reasoning, and what it revealed about the attacker’s behavior.

---

## Query 1 – Detecting Initial Access ( T1021.001 (Remote Desktop Protocol)

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType in ("RemoteInteractive", "RemoteInteractive_Logon")
| where ActionType == "LogonSuccess"
| summarize FirstSeen = min(TimeGenerated) by AccountName, RemoteIP
| order by FirstSeen asc
```
<img width="974" height="149" alt="image" src="https://github.com/user-attachments/assets/7bd14378-ee69-4655-8acd-a92c40960206" />

 
## Purpose and Explanation of the DeviceLogonEvents Query
---
The purpose of this query is to identify which user accounts successfully logged into the device `azuki-sl` during the initial breach window.  
It filters the `DeviceLogonEvents` table to only include events from November 19, 2025, to November 20, 2025, focusing on a precise time frame of interest.  
The query further narrows results to logons classified as `RemoteInteractive` or `RemoteInteractive_Logon`, which typically indicate remote access sessions such as RDP.  
Only successful logon attempts (`ActionType == "LogonSuccess"`) are considered, excluding failed attempts that are not relevant to initial access analysis.  
By summarizing the earliest (`min(TimeGenerated)`) successful logon per account and remote IP, the query highlights the first activity of each user on the device, which is critical for tracing initial access.  
Finally, ordering the results chronologically (`order by FirstSeen asc`) provides a clear timeline of account activity to support incident investigation and attribution efforts.


----
## Query 2 –  Initial Access: Compromised User Account ( kenji.sato MITRE: T1078 (Valid Accounts) 
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project TimeGenerated, AccountName, RemoteIP
```
<img width="955" height="361" alt="image" src="https://github.com/user-attachments/assets/c7f63a5c-e7bb-489f-9625-9a4b300eb6cb" />

## Purpose and Explanation of the DeviceLogonEvents Query for Specific Account
----
This query is designed to track the activity of the user account `kenji.sato` on the device `azuki-sl` during a specific timeframe.  
It filters the `DeviceLogonEvents` table to include only events between November 19, 2025, and November 20, 2025, focusing on the period relevant to the investigation.  
By specifying `AccountName == "kenji.sato"`, the query isolates this account from all other users to determine its exact activity on the device.  
The `project` operator selects only the most relevant fields: `TimeGenerated`, `AccountName`, and `RemoteIP`, reducing noise and making the output easier to analyze.  
This allows investigators to see when the account logged in and from which remote IP addresses, helping to confirm whether it was involved in initial access or suspicious activity.  
Overall, the query provides a clear, concise timeline of `kenji.sato`’s logon events on the device, supporting targeted forensic analysis and incident response.


```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project TimeGenerated, AccountName, RemoteIP
| where RemoteIP == "88.97.178.12"
```
<img width="800" height="297" alt="image" src="https://github.com/user-attachments/assets/74a8abd5-d92a-431e-9d98-a53beb0b0847" />

## Purpose and Explanation of the DeviceLogonEvents Query for Specific Account and IP
----

This query is designed to investigate the user account `kenji.sato` on the device `azuki-sl` during a defined time window.  
It filters the `DeviceLogonEvents` table to events between November 19, 2025, and November 20, 2025, targeting the timeframe of potential initial access.  
By specifying `AccountName == "kenji.sato"`, the query focuses exclusively on this user’s activity, excluding all other accounts.  
The `project` operator selects only the relevant fields: `TimeGenerated`, `AccountName`, and `RemoteIP`, simplifying the analysis for investigators.  
An additional filter `where RemoteIP == "88.97.178.12"` isolates logons originating from a specific IP address, helping to identify if this IP was used in the breach.  
This approach provides a precise view of when and from where `kenji.sato` accessed the device, supporting detailed forensic analysis and targeted incident response.


