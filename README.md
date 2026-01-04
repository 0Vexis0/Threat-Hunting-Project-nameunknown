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

# Thought Process Regarding Query 1 – Detecting Initial Access (T1021.001 Remote Desktop Protocol)

1. The goal is to identify which accounts successfully accessed the device via remote sessions during the suspected initial breach window.  
2. Filtering by `DeviceName == "azuki-sl"` isolates the specific host under investigation.  
3. Limiting the `TimeGenerated` to the defined timeframe ensures that only relevant events are analyzed.  
4. Filtering for `LogonType` values "RemoteInteractive" or "RemoteInteractive_Logon" targets RDP and other remote access methods that could have been exploited.  
5. Using `ActionType == "LogonSuccess"` ensures only successful logons are included, which are critical to trace initial access.  
6. Summarizing by the earliest logon per account and remote IP provides a timeline of initial access attempts, supporting incident investigation and attribution.

#2 Flag = kenji.sato
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

# Thought Process Regarding Query 2 – Initial Access: Compromised User Account (kenji.sato T1078 Valid Accounts)

1. The objective is to focus on a specific compromised account, `kenji.sato`, to verify its activity during the breach.  
2. Filtering by `DeviceName` ensures only the relevant endpoint is examined.  
3. Restricting `TimeGenerated` keeps the analysis within the window of interest.  
4. Filtering by `AccountName` isolates this user from all other accounts on the device.  
5. Projecting only `TimeGenerated`, `AccountName`, and `RemoteIP` simplifies the output to key forensic details for easier review.  
6. This query allows analysts to track the account's activity and validate if it was leveraged during the attack.

----
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

# Thought Process Regarding Query 3 – Specific Account and IP Activity (kenji.sato)

1. This query aims to trace activity for `kenji.sato` originating from a specific IP (`88.97.178.12`) on the compromised device.  
2. Filtering by `DeviceName` ensures only the host of interest is included.  
3. The `TimeGenerated` filter restricts analysis to the suspected breach timeframe.  
4. Projecting `TimeGenerated`, `AccountName`, and `RemoteIP` focuses on essential forensic information.  
5. Including the IP filter identifies which logons came from a particular remote source, critical for pinpointing the attacker’s origin.  
6. This precise filtering provides a detailed timeline of account activity associated with that IP, aiding targeted investigation.

#1 Flag = 88.97.178.12
----

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "-a"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| take 100
```
<img width="762" height="151" alt="image" src="https://github.com/user-attachments/assets/58da48a4-918c-4eec-ad80-2e1596e7056f" />

## Purpose and Explanation of the DeviceProcessEvents Query

The purpose of this query is to identify process activity executed by the user account `kenji.sato` on the device `azuki-sl` during the suspected breach window.  
It filters the `DeviceProcessEvents` table to a specific timeframe between November 19, 2025, and November 20, 2025, ensuring the analysis remains focused on relevant activity.  
By restricting results to the account `kenji.sato`, the query isolates processes launched under that user’s context, which is critical when validating potential attacker-controlled execution.  
The condition `ProcessCommandLine contains "-a"` is used to detect processes that were executed with specific command-line arguments, which may indicate suspicious or malicious behavior.  
The `project` statement limits the output to key forensic fields such as execution time, device name, account name, process filename, and full command line for analysis.  
Finally, the `take 100` operator caps the results to the first 100 records, making the output manageable while still providing sufficient data to identify abnormal process execution patterns.

# Thought Process Regarding Query 4 – Process Activity with "-a" Argument

1. The goal is to detect process execution by `kenji.sato` that includes the `-a` command-line argument, which may indicate unusual or attacker-driven execution.  
2. Filtering by `DeviceName` and `AccountName` isolates relevant events on the affected host and user.  
3. The `TimeGenerated` filter focuses on the window when the compromise likely occurred.  
4. Searching for `ProcessCommandLine contains "-a"` identifies processes executed with potentially malicious arguments.  
5. Projecting `TimeGenerated`, `DeviceName`, `AccountName`, `FileName`, and `ProcessCommandLine` provides the necessary forensic context.  
6. Limiting results with `take 100` ensures manageable output for analysis while highlighting abnormal process activity.

#3 Flag = ARP.EXE -a
----
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "attrib"
| where ProcessCommandLine contains "+h"
| where ProcessCommandLine contains "C:\\"
| project TimeGenerated, FileName, ProcessCommandLine
| take 100
```
<img width="781" height="122" alt="image" src="https://github.com/user-attachments/assets/2d06afbd-8493-4aef-862a-942052dc7571" />

## Purpose and Explanation of the DeviceProcessEvents Query

This query analyzes process activity on the device `azuki-sl` executed by the user account `kenji.sato` within a defined investigation window.  
It specifically focuses on commands containing `attrib`, a native Windows utility used to modify file and folder attributes.  
The filter for `+h` narrows the results to cases where files or directories were explicitly marked as hidden, which is a common stealth technique.  
Requiring the command line to include a `C:\` path ensures the action targeted an actual local file or folder on the system.  
The projected fields show when the action occurred, which executable was responsible, and the exact command that was run.  
Overall, this query is used to identify intentional attempts to conceal files or directories that may indicate post-compromise or persistence-related activity.

# Thought Process Regarding Query 5 – Hidden Files and Folders (attrib +h)

1. The purpose is to detect use of the `attrib` utility with the `+h` parameter to hide files, a common post-compromise stealth technique.  
2. Filtering by `DeviceName` and `AccountName` focuses on relevant host and user activity.  
3. The `TimeGenerated` range ensures only events during the suspected breach are analyzed.  
4. Requiring `ProcessCommandLine` to include `"attrib"`, `"+h"`, and `"C:\"` ensures detection of attempts to hide real files or directories.  
5. Projecting `TimeGenerated`, `FileName`, and `ProcessCommandLine` captures the time, tool used, and exact command.  
6. This query helps uncover attempts to conceal files or directories, indicating potential persistence or data staging activity.

#4 Flag = C:\ProgramData\WindowsCache
----
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains @"Windows Defender\Exclusions\Extensions"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```
<img width="746" height="92" alt="image" src="https://github.com/user-attachments/assets/209153ad-1317-4e08-bc49-e6e2bf3a6c07" />

## Purpose and Explanation of the DeviceRegistryEvents Query

This query looks at changes made to the computer’s registry, which is a system database that stores Windows settings.  
It focuses specifically on the device `azuki-sl` and searches in the registry path where **Windows Defender stores file types it should ignore**.  
The query projects the exact time each change happened, the registry key path, the name of the value changed (the file extension excluded), the data stored for that value, and the action type performed.  
Results are ordered chronologically (`order by TimeGenerated asc`) to provide a clear timeline of when exclusions were added.  
In this run, the query identified three file extensions that were excluded, meaning the attacker modified Defender to ignore those file types, allowing potentially malicious files to run undetected.  

- **HKLM (HKEY_LOCAL_MACHINE)** is a Windows registry hive that stores settings applying to the entire computer, not just a single user.  
- Changes under HKLM affect all users on the device, so any modifications (like Defender exclusions) apply system-wide, though not every registry key in HKLM represents the device itself—it represents system-wide configuration settings.

# Thought Process Regarding Query 6 – Windows Defender Excluded File Types

1. The objective is to identify modifications to Windows Defender exclusions for file types, which could indicate attempts to bypass antivirus.  
2. Filtering by `DeviceName` ensures the query focuses on the target system.  
3. Searching `RegistryKey contains "Exclusions\Extensions"` targets the registry area where Defender stores ignored file types.  
4. Projecting key fields like `TimeGenerated`, `RegistryKey`, `RegistryValueName`, `RegistryValueData`, and `ActionType` captures necessary forensic details.  
5. Ordering by `TimeGenerated` provides a chronological view of exclusion events.  
6. The results help analysts determine which file types were excluded and assess if they facilitated malicious activity.

#5 Flag = 3
----
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains @"Windows Defender\Exclusions\Paths"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```
<img width="751" height="164" alt="image" src="https://github.com/user-attachments/assets/0de144b8-daa1-43b2-b545-e3a3c644efe0" />

## Purpose and Explanation of the DeviceRegistryEvents Query for Defender Excluded Paths

This query looks at registry activity, which records changes made to important Windows system settings.  
It focuses only on the device named `azuki-sl` and searches the exact area of the registry where Windows Defender stores folder paths it has been told to ignore.  
By filtering for `Exclusions\Paths`, the query isolates cases where a folder was added to Defender’s exclusion list, meaning Defender will no longer scan files inside that directory.  
The results show when the change happened, the registry location, and—most importantly—the folder path itself, which appears in the `RegistryValueName` field.  
Because attackers commonly choose temporary or system folders to store tools and downloads, seeing a temporary directory listed here strongly suggests it was used as a staging area for malware.  
Once that folder was excluded, Windows Defender would skip scanning anything inside it, allowing malicious files to run without being detected.

# Thought Process Regarding Query 7 – Windows Defender Excluded Paths

1. The goal is to detect registry changes where folders were added to Windows Defender’s exclusion list.  
2. Filtering by `DeviceName` targets the specific compromised host.  
3. Searching `RegistryKey contains "Exclusions\Paths"` isolates registry changes affecting folder scanning.  
4. Projecting `TimeGenerated`, `RegistryKey`, `RegistryValueName`, `RegistryValueData`, and `ActionType` provides complete context.  
5. Ordering by `TimeGenerated` creates a timeline of when exclusions occurred.  
6. Identifying temporary or system folders in the exclusions can reveal staging areas used by attackers to evade detection.

#6 Flag = C:\Users\KENJI~1.SAT\AppData\Local\Temp
----
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "http"
| where ProcessCommandLine contains ".exe"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="760" height="43" alt="image" src="https://github.com/user-attachments/assets/d9c627ab-949a-4b42-820b-54102877e04e" />
## Purpose and Explanation of the DeviceProcessEvents Query for Internet-Downloaded Executables

This query examines processes run on the device `azuki-sl` that involve potential file downloads from the internet.  
It filters for command lines containing `http`, indicating a web address, and `.exe`, showing that the file involved was an executable.  
Together, these conditions isolate processes likely used to download a program rather than normal browsing or file access.  
The query projects `TimeGenerated`, `FileName`, `ProcessCommandLine`, and `InitiatingProcessAccountName`, providing details on when the command ran, which executable launched it, the full command line, and the user responsible.  
This makes it easier to identify suspicious behavior or unauthorized downloads on the system.  
If `certutil.exe` appears in the `FileName` column, it indicates the attacker used this legitimate Windows utility to download files from a URL, which is a common post-compromise technique.

# Thought Process Regarding Query 8 – Internet-Downloaded Executables

1. The objective is to identify processes that likely downloaded executables from the internet.  
2. Filtering by `DeviceName` ensures only the host under investigation is analyzed.  
3. Searching for `ProcessCommandLine contains "http"` and `.exe` isolates network-based executable downloads.  
4. Projecting `TimeGenerated`, `FileName`, `ProcessCommandLine`, and `InitiatingProcessAccountName` provides details on the download activity.  
5. Ordering by `TimeGenerated` creates a chronological view of potential malicious downloads.  
6. The query highlights the use of utilities like `certutil.exe` by attackers to retrieve payloads, supporting detection of post-compromise activity.

#7 Flag = certutil.exe
----
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project 
    TimeGenerated,
    DeviceName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="790" height="107" alt="image" src="https://github.com/user-attachments/assets/5ecb6703-8251-462f-80af-950cccb27d2b" />

## Purpose and Explanation of the DeviceProcessEvents Query for Scheduled Task Creation

This query searches `DeviceProcessEvents` to identify executions of `schtasks.exe` on the device `azuki-sl`, the Windows utility used to create and manage scheduled tasks.  
By filtering for command lines containing the `/create` parameter, the query isolates events where a new scheduled task was created, excluding modifications or queries of existing tasks.  
Scheduled task creation is important because it allows code to run automatically on a defined schedule without user interaction.  
Attackers often abuse this behavior to ensure their payload persists across system reboots or user logoffs.  
The projected fields (`TimeGenerated`, `DeviceName`, `FileName`, `ProcessCommandLine`, `InitiatingProcessAccountName`) reveal the exact command used, including the task name and executable, helping differentiate malicious tasks from legitimate ones.  
This activity maps directly to the MITRE ATT&CK **Persistence** tactic, specifically Scheduled Task creation, establishing long-term, reliable access to the compromised system.

# Thought Process Regarding Query 9 – Scheduled Task Creation

1. The goal is to detect creation of scheduled tasks using `schtasks.exe`, which is often abused for persistence.  
2. Filtering by `DeviceName` targets the specific system of interest.  
3. Searching `FileName == "schtasks.exe"` and `ProcessCommandLine contains "/create"` isolates new task creation events.  
4. Projecting `TimeGenerated`, `DeviceName`, `FileName`, `ProcessCommandLine`, and `InitiatingProcessAccountName` provides full context of the task and the user who created it.  
5. Ordering chronologically allows analysts to see when tasks were created relative to other attacker activity.  
6. Detecting scheduled task creation maps to the MITRE ATT&CK Persistence tactic and helps identify long-term access mechanisms used by attackers.

#8 Flag 8 = Windows Update Check
----

## Section 1 Summary – Initial Access and Early Attacker Activity

Section 1 focuses on identifying how the attacker gained initial access to the device `azuki-sl` and what actions they performed immediately after compromise.  
Using `DeviceLogonEvents`, the analysis established which accounts successfully logged in during the initial breach window (November 19–20, 2025), highlighting the use of remote access via RDP (T1021.001).  
The account `kenji.sato` was flagged as compromised, with logons traced to a specific IP address (`88.97.178.12`), confirming unauthorized access from an external source.  
`DeviceProcessEvents` queries revealed suspicious process execution, including command-line usage with the `-a` argument, hiding files using `attrib +h`, and downloading executables from the internet (`http` and `.exe` in command lines), indicating attacker-controlled activity and attempts to conceal tools.  
Registry analysis showed modifications to Windows Defender exclusions for both file types and folder paths, allowing malicious files to run undetected, while scheduled task creation using `schtasks.exe` demonstrated persistence tactics.  
Overall, Section 1 maps the attacker's early activity, from initial access through lateral movement, stealth, and persistence, providing a detailed timeline of compromise and supporting forensic investigation and mitigation planning.


## Section 2 – Command & Control, Credential Access, Exfiltration, and Lateral Movement Analysis
----
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project 
    TimeGenerated,
    DeviceName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="370" height="54" alt="image" src="https://github.com/user-attachments/assets/595d8079-d7d9-40d0-96e1-e3618c41babe" />

### Purpose and Explanation

This query analyzes **DeviceProcessEvents** on the host `azuki-sl` to identify executions of `schtasks.exe` that include the `/create` parameter, which indicates the creation of a new scheduled task. Scheduled tasks are a common persistence mechanism because they allow code to execute automatically at boot, logon, or on a timer without further user interaction. By projecting the full command line and initiating account, the query exposes exactly what was scheduled to run and who created it. In this case, the output confirms that a scheduled task was created to execute the malicious binary located at `C:\ProgramData\WindowsCache\svchost.exe`, directly tying persistence to the identified malware.

### Thought Process (Why the Same Query Was Used for Flag 9)

1. The objective was to identify persistence via scheduled task creation, which requires visibility into `schtasks.exe` executions.  
2. Filtering on `DeviceName` ensures the activity is scoped only to the compromised system.  
3. Using `FileName == "schtasks.exe"` and `ProcessCommandLine contains "/create"` isolates only new task creation events, excluding benign queries or deletions.  
4. This same logic was reused for Flag 9 because the persistence artifact was expected to be the same malware already identified earlier in the investigation.  
5. Reviewing the `ProcessCommandLine` reveals the exact payload path, allowing confirmation that `C:\ProgramData\WindowsCache\svchost.exe` was the executable configured to persist.  
6. Reusing the same query ensures consistency across flags and validates that the scheduled task creation directly supports long‑term attacker access.

#9 Flag 9 = C:\ProgramData\WindowsCache\svchost.exe
----
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFolderPath has "WindowsCache"
| summarize count() by RemoteIP
```
<img width="998" height="106" alt="image" src="https://github.com/user-attachments/assets/14efeca1-61df-44e4-a32e-7705b7cd9d7f" />

### Purpose and Explanation

This query examines **DeviceNetworkEvents** on the host `azuki-sl` during the attack timeframe to identify outbound network connections initiated by processes running from the `WindowsCache` directory. Filtering on this folder path ensures the results are limited to network activity generated by the confirmed malicious `svchost.exe` rather than legitimate system processes. By summarizing events by `RemoteIP`, the query highlights external addresses that the malware repeatedly contacted. The resulting IP address, `78.141.196.6`, is identified as the command-and-control (C2) server used by the attacker to communicate with the compromised system.

### Thought Process

1. The goal was to identify command-and-control infrastructure used by the malware after execution.  
2. Filtering by `DeviceName` and the specific time range narrows the scope to the confirmed compromise window on the affected host.  
3. Using `InitiatingProcessFolderPath has "WindowsCache"` isolates network traffic generated only by the malicious binary’s execution path.  
4. Summarizing by `RemoteIP` surfaces external addresses contacted by the malware instead of individual connection events.  
5. The IP with repeated connections stands out as infrastructure rather than a one-off connection.  
6. This approach directly reveals `78.141.196.6` as the C2 server used to maintain remote control of the infected system.

#10 Flag 10 = 78.141.196.6
----
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFolderPath has "WindowsCache"
| summarize Connections = count() by RemoteIP, RemotePort
| order by Connections desc
```
<img width="673" height="144" alt="image" src="https://github.com/user-attachments/assets/0ad7a711-876b-4e60-9899-476cd3d06b67" />

### Purpose and Explanation

This query analyzes **DeviceNetworkEvents** on the host `azuki-sl` during the attack window to determine how the malware communicated with its external command-and-control infrastructure. By filtering on the `WindowsCache` folder path, the query limits results to network traffic generated by the malicious `svchost.exe`. Summarizing connections by both `RemoteIP` and `RemotePort` reveals not only the external destination but also the specific service port used for communication. The results show that the C2 traffic consistently used port **443**, indicating the attacker leveraged HTTPS to blend malicious traffic with normal encrypted web activity.

### Thought Process

1. The objective was to identify the network port used by the malware for command-and-control communication.  
2. Restricting the query to the compromised host and time range ensures only relevant attack activity is analyzed.  
3. Filtering on `InitiatingProcessFolderPath has "WindowsCache"` isolates traffic originating from the malicious binary rather than legitimate applications.  
4. Grouping by `RemoteIP` and `RemotePort` exposes the communication pattern instead of individual network events.  
5. Ordering by connection count highlights the primary channel used by the malware.  
6. The dominance of port **443** confirms the attacker used HTTPS for C2 traffic to evade detection and appear as normal web traffic.

#11 Flag 11 = 443
----
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName matches regex @"^[a-zA-Z0-9]{1,3}\.exe$"
| where FolderPath has_any ("Temp", "ProgramData", "AppData", "WindowsCache")
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="758" height="153" alt="image" src="https://github.com/user-attachments/assets/fdc2c119-33bb-4a4f-84e6-a26e54cac2f7" />

### Purpose and Explanation

This query examines **DeviceFileEvents** on the host `azuki-sl` during the defined attack window to identify suspicious executable files created or written to disk. It focuses on executables with extremely short names, which are commonly used by attackers to evade attention and signature-based detection. By limiting results to directories such as `Temp`, `ProgramData`, `AppData`, and `WindowsCache`, the query targets locations frequently abused for malware staging. The results reveal **mm.exe**, identifying it as the malicious executable dropped during the compromise.

### Thought Process

1. The goal was to detect a credential theft or staging tool dropped onto the system during the intrusion.  
2. Filtering by a short filename regex isolates executables that are unlikely to be legitimate applications.  
3. Restricting folder paths to common staging directories narrows results to locations attackers typically abuse.  
4. Projecting the initiating process provides context on how the file was created or delivered.  
5. Ordering results chronologically helps pinpoint when the malicious file first appeared.  
6. The appearance of **mm.exe** in a suspicious directory during the attack window confirms it as the malicious payload associated with credential access.

#12 Flag 12 = mm.exe
----
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has "::"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="753" height="93" alt="image" src="https://github.com/user-attachments/assets/bfe430a8-9208-4a0e-9334-009042f5e613" />

### Purpose and Explanation

This query analyzes **DeviceProcessEvents** on the host `azuki-sl` during the attack timeframe to identify execution of credential-dumping activity. It filters for command lines containing `::`, a syntax commonly used by credential theft tools to invoke internal modules. This allows the query to focus on how credentials were accessed rather than just which executable was run. The output reveals the command **sekurlsa::logonpasswords**, confirming that credentials were extracted directly from system memory.

### Thought Process

1. The objective was to identify the exact credential-dumping technique used by the attacker.  
2. Filtering by `ProcessCommandLine has "::"` targets known module-based credential dumping syntax.  
3. Limiting results to the attack time window ensures relevance to the active compromise.  
4. Projecting the full command line exposes the precise module and function executed.  
5. Ordering results chronologically highlights the first occurrence of credential access.  
6. The presence of **sekurlsa::logonpasswords** confirms memory-based credential extraction consistent with credential access tactics.


#13 Flag 13 = mm.exesekurlsa::logonpasswords
----
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".zip"
| where FolderPath has_any ("Temp", "ProgramData", "AppData", "WindowsCache")
```
<img width="768" height="122" alt="image" src="https://github.com/user-attachments/assets/94cf5bc7-f655-4372-8212-e73dab69b76b" />

### Purpose and Explanation

This query examines **DeviceFileEvents** on the host `azuki-sl` during the attack window to identify compressed archive files created or handled by the attacker. It filters for files ending in `.zip`, which are commonly used to package stolen data before exfiltration. The query further narrows results to directories such as `Temp`, `ProgramData`, `AppData`, and `WindowsCache`, which are frequently abused by attackers for staging data. The output identifies **export-data.zip**, indicating it was used as a data staging archive prior to exfiltration.

### Thought Process

1. The goal was to identify evidence of data collection and staging prior to exfiltration.  
2. Filtering for `.zip` files targets compressed archives commonly used to bundle stolen data.  
3. Restricting results to known staging directories increases the likelihood of malicious relevance.  
4. Applying the time window ensures the file activity aligns with the compromise period.  
5. Reviewing the resulting file names isolates suspicious artifacts created during the attack.  
6. The presence of **export-data.zip** confirms that collected data was packaged for later exfiltration.

#14 Flag 14 = export-data.zip
----
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemotePort == 443
| where InitiatingProcessCommandLine contains @"C:\ProgramData\WindowsCache\export-data.zip"
| project 
    TimeGenerated,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemoteUrl,
    Protocol
| order by TimeGenerated asc
```
<img width="1443" height="199" alt="image" src="https://github.com/user-attachments/assets/fe010e2d-3b84-4d6a-8313-fb83d53dde56" />
### Purpose and Explanation

This query analyzes **DeviceNetworkEvents** on the host `azuki-sl` during the compromise window to identify how staged data was exfiltrated. It filters for network connections over port **443**, which captures encrypted HTTPS traffic commonly used to hide data transfers. By requiring the initiating process command line to reference `C:\ProgramData\WindowsCache\export-data.zip`, the query directly links outbound network activity to the staged archive file. The projected fields reveal the destination service, showing that **Discord** was used as the exfiltration channel.

### Thought Process

1. The objective was to determine where the staged ZIP file was sent after collection.  
2. Filtering on `RemotePort == 443` isolates HTTPS traffic, a common method for covert exfiltration.  
3. Matching the command line to `export-data.zip` ensures only traffic related to the staged archive is included.  
4. Projecting `RemoteUrl` and `RemoteIP` exposes the external service receiving the data.  
5. Ordering events chronologically ties the upload activity directly to the staging phase.  
6. The appearance of **Discord** in the results confirms it was abused as the data exfiltration platform.

#15 Flag 15 = discord
----
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has_any ("cl", "clear-log")
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="753" height="206" alt="image" src="https://github.com/user-attachments/assets/563ab83d-53c5-4066-ac83-cdec5ab59aae" />

### Purpose and Explanation

This query examines **DeviceProcessEvents** on the host `azuki-sl` during the attack window to identify evidence of log tampering. It specifically filters for executions of **wevtutil.exe**, a native Windows utility used to manage and clear event logs. By narrowing results to command-line arguments such as `cl` or `clear-log`, the query isolates actions where logs were deliberately erased. The earliest command observed, `wevtutil.exe cl Security`, confirms that the **Security** event log was cleared first, followed by Application and System logs, indicating an intentional effort to remove forensic evidence of the intrusion.

### Thought Process

1. The goal was to determine whether the attacker attempted to cover their tracks by deleting Windows event logs.  
2. Filtering by `DeviceName` and time range restricts results to the confirmed compromised host and attack period.  
3. Searching for `wevtutil.exe` targets the primary Windows tool used for clearing event logs.  
4. Including command-line arguments like `cl` and `clear-log` ensures only log deletion activity is captured.  
5. Sorting results chronologically reveals the order in which logs were cleared.  
6. The **Security** log appearing first confirms it was prioritized to erase authentication and privilege-related evidence.


#16 Flag 16 = Security
----
```kql
DeviceEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType in (
    "UserAccountCreated",
    "LocalUserCreated",
    "UserAccountAddedToLocalGroup"
)
| project
    TimeGenerated,
    ActionType,
    AccountName,
    AdditionalFields
| order by TimeGenerated asc
```
<img width="727" height="139" alt="image" src="https://github.com/user-attachments/assets/d8111457-1f87-4e72-8840-3cca7d9a0798" />

### Purpose and Explanation

This query analyzes **DeviceEvents** on the host `azuki-sl` during the compromise window to identify account-related changes made by the attacker. It filters for actions associated with user creation and privilege assignment, such as `UserAccountCreated`, `LocalUserCreated`, and `UserAccountAddedToLocalGroup`. By focusing on these event types, the query captures the direct outcome of account manipulation rather than indirect indicators. The results reveal a newly created account named **support**, which does not align with known legitimate users and indicates a persistence mechanism established by the attacker.

### Thought Process

1. The objective was to determine whether the attacker created or modified user accounts for long-term access.  
2. Restricting the query to the affected device and attack timeframe ensures relevance to the incident.  
3. Filtering on account creation and group assignment events isolates true persistence actions.  
4. Projecting account names and supporting details provides visibility into which users were added or modified.  
5. Ordering events chronologically shows when persistence was established in the attack timeline.  
6. The creation of the **support** account confirms the attacker implemented a stealth backdoor using a benign-looking username.

#17 Flag 17 = Support
----
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessAccountName == "kenji.sato"
| where FileName !contains "script"
| where ActionType in ("FileCreated", "FileWritten")
| where FileName endswith ".ps1"
| project
    TimeGenerated,
    FileName,
    FolderPath,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="766" height="117" alt="image" src="https://github.com/user-attachments/assets/27720aa0-eaad-4be6-9d9d-f9e7b4de6d7d" />

### Purpose and Explanation

This query examines **DeviceFileEvents** on the host `azuki-sl` during the attack timeframe to identify malicious PowerShell script activity. It filters for `.ps1` files that were created or written by the compromised user account `kenji.sato`, ensuring the activity is tied directly to the attacker’s execution context. By excluding filenames containing the word `script`, the query reduces noise from benign or administrative PowerShell usage. The results identify **wupdate.ps1**, indicating a malicious PowerShell script deployed to automate attacker actions such as payload execution, persistence setup, or follow-on command execution.

### Thought Process

1. The objective was to identify attacker-controlled PowerShell scripts used during execution.  
2. Filtering by `DeviceName` and the specific time window restricts results to the confirmed compromise period.  
3. Limiting results to files created or written by `kenji.sato` ties script creation directly to the compromised account.  
4. Focusing on `.ps1` files isolates PowerShell-based execution techniques commonly abused by attackers.  
5. Excluding generic script names reduces false positives from legitimate automation.  
6. The identification of **wupdate.ps1** confirms the attacker used a PowerShell script as an execution and orchestration mechanism.

#18 Flag 18 = wupdate.ps1
----
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName in ("mstsc.exe", "cmdkey.exe")
| where ProcessCommandLine has_any ("mstsc", "cmdkey", "/add", "/generic")
| project
    TimeGenerated,
    FileName,
    ProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="762" height="127" alt="image" src="https://github.com/user-attachments/assets/d49685e6-99a8-402b-a6ec-3d8dd7574771" />

### Purpose and Explanation

This query analyzes **DeviceProcessEvents** on the host `azuki-sl` during the compromise window to identify evidence of lateral movement using native Windows tools. It filters for executions of `mstsc.exe` and `cmdkey.exe`, which together indicate credential caching followed by a Remote Desktop connection. The command-line filters isolate usage patterns consistent with adding stored credentials and initiating RDP sessions. The results reveal a connection targeting **10.1.0.188**, a private RFC1918 address, confirming internal lateral movement rather than external communication. This demonstrates that the attacker expanded access to another internal system using legitimate administrative utilities.

### Thought Process

1. The goal was to detect lateral movement activity using built-in Windows tools instead of custom malware.  
2. Filtering by `DeviceName` and the attack timeframe narrows results to relevant post-compromise behavior.  
3. Targeting `mstsc.exe` and `cmdkey.exe` focuses on a common attacker sequence of credential storage followed by RDP access.  
4. Command-line filters (`/add`, `/generic`, `mstsc`) confirm the tools were used for remote authentication and connection.  
5. Extracting the destination from the command line identifies **10.1.0.188** as the target system.  
6. Because the IP falls within a private address range, this activity confirms internal lateral movement within the network.

#19 Flag 19 =  10.1.0.188
----
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "mstsc.exe"
| where ProcessCommandLine has_any ("/v:", "10.", "192.168.", "172.")
| project
    TimeGenerated,
    FileName,
    ProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="1226" height="199" alt="image" src="https://github.com/user-attachments/assets/32654418-9004-49bf-bc70-8070f17af471" /> 

### Purpose and Explanation

This query examines **DeviceProcessEvents** on the host `azuki-sl` during the defined attack window to identify explicit use of the Windows Remote Desktop client. It filters specifically for executions of `mstsc.exe`, confirming that Remote Desktop Connection was the tool used. The command-line conditions isolate cases where a remote host or internal IP address was specified, proving the process was actively initiating a connection rather than merely being present. Because `mstsc.exe` is a native administrative utility, its use allows attacker activity to blend in with legitimate system management. Overall, the query confirms that Remote Desktop was the remote access mechanism used for lateral movement within the environment.

### Thought Process

1. The objective was to confirm which remote access tool was used for lateral movement.  
2. Filtering by `DeviceName` and the attack timeframe ensures only relevant compromise activity is captured.  
3. Restricting results to `FileName == "mstsc.exe"` directly identifies the Windows Remote Desktop client.  
4. Command-line filters for `/v:` and private IP ranges verify that an actual remote connection was initiated.  
5. Projecting the full command line and initiating context provides attribution to the user and parent process.  
6. Identifying `mstsc.exe` as the execution tool confirms the attacker relied on native RDP functionality to move laterally while avoiding detection.

#20 Flag 20 =  mstsc.exe
----

## Section 3 – Post-Compromise Re-Entry, Discovery, and Defense Evasion Analysis
This section documents the attacker’s return to the environment after the initial compromise and details how access was re-established, expanded, and reinforced. Logon telemetry across azuki-related systems shows renewed successful authentications after November 22, 2025, confirming the attacker regained access rather than operating continuously. The presence of multiple azuki systems, including azuki-adminpc and azuki-fileserver01, indicates the intrusion expanded beyond the original host and into higher-value infrastructure. The use of the fileadmin account during these logons demonstrates that an administrative account was compromised and leveraged during this later phase of activity.

Following re-entry, the attacker conducted systematic discovery to map the environment. Execution of net.exe with the share argument confirms local share enumeration, while net.exe commands containing UNC paths show remote share discovery against internal systems such as 10.1.0.188. Additional execution of whoami.exe reveals privilege enumeration to confirm access level, and ipconfig.exe /all demonstrates network configuration discovery to understand domain and network layout. These actions reflect deliberate reconnaissance consistent with preparing for further lateral movement or data access.

Defense evasion and data staging activity further confirms attacker intent. The use of attrib.exe with +h and +s flags shows deliberate hiding of directories to conceal staged artifacts. The chosen staging path, C:\Windows\Logs\CBS, is a legitimate Windows directory that blends in with system components, reducing the likelihood of detection. Finally, certutil.exe with the -urlcache option was used to download a PowerShell script into this hidden directory, linking defense evasion, staging, and execution together into a cohesive post-compromise workflow.

Overall, this section demonstrates a structured second-phase intrusion in which the attacker re-entered the environment using compromised credentials, enumerated systems and privileges, hid operational artifacts, and staged additional tooling. These actions indicate a controlled and methodical adversary focused on persistence, internal awareness, and continued operational capability rather than opportunistic access.
----
```kql
DeviceLogonEvents
| where TimeGenerated >= datetime(2025-11-22)
| where DeviceName contains "azuki"
```
<img width="1440" height="157" alt="image" src="https://github.com/user-attachments/assets/fca4b2a5-de0f-47f1-b01e-d7df7c23c9f9" />

The query DeviceLogonEvents | where DeviceName contains "azuki" is used to identify all logon events for devices related to the “azuki” environment. By running this, I was able to see which devices had activity that hadn’t been fully investigated yet. Parsing through the results highlighted azuki-adminpc as a device with multiple logon entries, suggesting it may contain additional evidence worth examining.

The query DeviceLogonEvents | where DeviceName contains "azuki" is used to identify all logon events for devices related to the “azuki” environment. By running this, I was able to see which devices had activity that hadn’t been fully investigated yet. Parsing through the results highlighted azuki-adminpc as a device with multiple logon entries, suggesting it may contain additional evidence worth examining. 

```kql
DeviceLogonEvents
| where DeviceName contains "azuki"
| where ActionType in ("LogonSuccess", "LogonSucceeded")
| where isnotempty(RemoteIP)
| where TimeGenerated >= datetime(2025-11-22)
| summarize arg_min(TimeGenerated, *) by DeviceName
| project TimeGenerated, DeviceName, AccountName, RemoteIP
```
<img width="768" height="107" alt="image" src="https://github.com/user-attachments/assets/d0690b9a-a8eb-43fb-8fd8-38eb8ee8d9e0" /> 

Combined with the subsequent query that filtered for remote IPs, the analysis narrowed the results to just a few IPs, including the external attacker IP, making it much clearer that the attacker had successfully regained access to the environment.The query that filtered DeviceLogonEvents for azuki-related devices returned multiple entries, including the file server. Parsing the results showed azuki-fileserver01 as the device involved in suspicious logon activity. This indicates that the file server was accessed during the attack, suggesting it may have been compromised or used by the attacker to move laterally. Identifying this device helps focus further investigation on sensitive systems that could contain critical data or be leveraged for persistence.

#21 Flag 21 = 159.26.106.98
#22 Flag 22 = azuki-fileserver01
#23 Flag 23 =fileadmin
----

