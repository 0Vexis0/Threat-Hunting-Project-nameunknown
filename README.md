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

## Query 1 – Initial Access: Compromised User Account ( Flag 88.97.178.12 MITRE: T1078 (Valid Accounts), T1021.001 (Remote Desktop Protocol)

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project TimeGenerated, AccountName, RemoteIP
```

Purpose

Identify whether the user account kenji.sato was used to authenticate to the system during the suspected initial access window.

Explanation

This query reviews authentication events on azuki-sl for a single user account over a narrow time range. By isolating logons tied to kenji.sato, the investigation confirms whether valid credentials were used rather than an exploit or brute-force attempt. The output focuses on timestamps and source IPs to establish an external origin.

This establishes the foundation of the intrusion: valid account abuse
