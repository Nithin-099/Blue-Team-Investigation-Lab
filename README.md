# Blue Team Investigation Lab

![Status](https://img.shields.io/badge/Status-Active-green)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![Splunk](https://img.shields.io/badge/SIEM-Splunk-orange)
![Platform](https://img.shields.io/badge/Platform-TryHackMe%20%7C%20CyberDefenders-blue)

## Overview
A collection of hands-on blue team investigations
completed on TryHackMe and CyberDefenders platforms.
Each investigation simulates a real-world security
incident and demonstrates core SOC analyst skills
including SIEM investigation, network forensics,
phishing analysis, threat actor attribution, and
professional incident documentation.

All reports follow the NIST Incident Response
framework and include full MITRE ATT&CK mapping.

---

## Investigations Completed

| # | Investigation | Platform | Category | Difficulty | Status |
|---|---------------|----------|----------|------------|--------|
| 1 | Investigating with Splunk | TryHackMe | SIEM Investigation | Medium | ✅ Complete |
| 2 | BlueSky Ransomware | CyberDefenders | Network Forensics | Medium | ✅ Complete |
| 3 | GrabThePhisher | CyberDefenders | Phishing Kit Analysis | Easy | ✅ Complete |

---

## Skills Demonstrated

| Skill | Tool | Evidence |
|-------|------|---------|
| SIEM investigation | Splunk | 17,172 events analyzed |
| SPL query writing | Splunk | 8 custom queries written |
| Network forensics | Wireshark | 4,797 packets analyzed |
| Phishing kit analysis | VS Code, Terminal | PHP source code analyzed |
| Attacker identification | Splunk, Wireshark | 3 attacker IPs identified |
| Attack tool detection | Splunk | sqlmap, Havij, zgrab, Webshell |
| Credential analysis | Wireshark | NTLM hashes, SQL creds found |
| Threat actor attribution | Terminal | Developer alias identified |
| Telegram C2 analysis | CyberChef | Bot token + Chat ID extracted |
| Data exfiltration analysis | Splunk | 126,167 bytes measured |
| IOC extraction | All tools | 30+ IOCs documented |
| MITRE ATT&CK mapping | ATT&CK Navigator | 13 techniques mapped |

---

## Investigation Summaries

### 1. Investigating with Splunk — TryHackMe

Tool: Splunk Enterprise 8.2
Log Types: Web traffic + Firewall logs
Events: 17,172 web traffic events

Scenario:
Web server tbfc.thm reported suspicious
activity. Using Splunk SPL queries, analyzed
web traffic and firewall logs to identify
attacker, attack techniques, and data theft.

Key Findings:
→ Attacker IP 198.51.100.55 responsible
for 45.8% of ALL web traffic (7,876 events)
→ 8 malicious tools identified: sqlmap,
Havij, zgrab, Webshell Runner and more
→ LFI attack successfully read /etc/passwd
(HTTP 200 confirmed exploitation)
→ Webshell deployed via /upload.php
(Ruby/2.7.0 Webshell Runner confirmed)
→ Internal host 10.10.1.5 made 285 C2
connections to attacker on port 8080
→ 126,167 bytes exfiltrated via C2 channel

MITRE Techniques Mapped: 8
T1595, T1190, T1505.003, T1083,
T1005, T1071.001, T1041, T1595.002


---

### 2. BlueSky Ransomware — CyberDefenders

Tool: Wireshark
File: BlueSkyRansomware.pcap
Packets: 4,797

Scenario:
Ransomware attack reported on a Windows
SQL Server. Analyzed network packet capture
to reconstruct the complete attack chain
from initial access through lateral movement.

Key Findings:
→ SQL Server compromised via default SA
account (sa / cyb3rd3f3nd3r$)
→ xp_cmdshell enabled for OS command
execution via SQL queries
→ checking.ps1 downloaded from Python
C2 server (SimpleHTTP/0.6 Python/3.11.8)
→ Windows Defender completely disabled
including MBAM and Sophos services
→ Persistence via scheduled task disguised
as legitimate Windows maintenance task
→ NTLM hashes dumped via Invoke-PowerDump
(Administrator, Guest, Carlos accounts)
→ Lateral movement via Invoke-SMBExec
using Pass-the-Hash technique

MITRE Techniques Mapped: 9
T1046, T1078, T1505.001, T1059.001,
T1562.001, T1053.005, T1003.002,
T1021.002, T1071.001


---

### 3. GrabThePhisher — CyberDefenders

Tools: Linux Terminal, VS Code, CyberChef
Category: Phishing Kit Analysis

Scenario:
A MetaMask cryptocurrency wallet phishing
kit was discovered on a compromised server.
Analyzed the kit's source code to identify
attacker infrastructure, stolen credentials,
and threat actor identity.

Key Findings:
→ Wallet targeted: MetaMask (Ethereum)
→ Seed phrases stolen via fake login page
→ Telegram Bot API used for real-time
credential delivery to attacker
→ Bot Token: 5457463144:AAG8t4k7e...
→ Chat ID: 5442785564
→ Developer alias: j1j1b1s@m3r0
→ Victim geo-tracking via sypexgeo API
→ All stolen data logged to /log/log.txt

MITRE Techniques Mapped: 4
T1566, T1056, T1102, T1056.003


---

## IOC Master List

### Splunk Investigation
| IOC | Type | Description |
|-----|------|-------------|
| 198.51.100.55 | IP | Primary attacker |
| 10.10.1.5 | IP | Compromised internal host |
| 8080 | Port | C2 communication port |
| Ruby/2.7.0 (Webshell Runner) | User Agent | Webshell confirmed |
| sqlmap/1.7.9 | User Agent | SQLi tool |
| Havij/1.17 | User Agent | Automated SQLi |
| /download?file=../../etc/passwd | URL | LFI payload |
| /?redirect=http://evil.site | URL | Open redirect |
| 126,167 | Bytes | Data exfiltrated |

### BlueSky Ransomware
| IOC | Type | Description |
|-----|------|-------------|
| 87.96.21.84 | IP | Attacker C2 server |
| 87.96.21.81 | IP | Victim SQL server |
| cyb3rd3f3nd3r$ | Credential | Compromised SA password |
| sivVZ | Hostname | Attacker client name |
| SimpleHTTP/0.6 Python/3.11.8 | Server | C2 server type |
| checking.ps1 | File | Initial payload |
| Invoke-PowerDump.ps1 | File | Credential dumper |
| Invoke-SMBExec.ps1 | File | Lateral movement |

### GrabThePhisher
| IOC | Type | Description |
|-----|------|-------------|
| 5457463144:AAG8t4k7e... | Token | Telegram bot token |
| 5442785564 | ID | Telegram chat ID |
| j1j1b1s@m3r0 | Alias | Threat actor identity |
| api.sypexgeo.net | Domain | Geo tracking API |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Investigation |
|--------|-----------|-----|---------------|
| Reconnaissance | Active Scanning | T1595 | Splunk |
| Reconnaissance | Vulnerability Scanning | T1595.002 | Splunk |
| Initial Access | Exploit Public App | T1190 | Splunk |
| Initial Access | Valid Accounts | T1078 | BlueSky |
| Initial Access | Phishing | T1566 | GrabThePhisher |
| Execution | PowerShell | T1059.001 | BlueSky |
| Execution | SQL Stored Procedures | T1505.001 | BlueSky |
| Execution | Web Shell | T1505.003 | Splunk |
| Persistence | Scheduled Task | T1053.005 | BlueSky |
| Defense Evasion | Disable Security Tools | T1562.001 | BlueSky |
| Credential Access | SAM Dumping | T1003.002 | BlueSky |
| Credential Access | Input Capture | T1056 | GrabThePhisher |
| Discovery | File Discovery | T1083 | Splunk |
| Lateral Movement | SMB/Admin Shares | T1021.002 | BlueSky |
| Collection | Data from Local System | T1005 | Splunk |
| Command & Control | Web Protocols | T1071.001 | Splunk + BlueSky |
| Command & Control | Web Service | T1102 | GrabThePhisher |
| Exfiltration | Exfil Over C2 | T1041 | Splunk |

---

## How to Use This Repository

Each investigation folder contains a complete report
written in professional SOC analyst style following
the NIST Incident Response framework:

**Detection** → Identifying attacker activity in logs
**Analysis** → Reconstructing the full attack chain
**Containment** → Documenting containment actions
**Lessons Learned** → Key takeaways for defenders

Each report includes:
- Complete attack timeline
- All IOCs discovered
- MITRE ATT&CK technique mapping
- Evidence screenshots
- Remediation recommendations
- Lessons learned for SOC analysts

---

## Tools Used Across All Investigations

| Tool | Purpose |
|------|---------|
| Splunk Enterprise 8.2 | SIEM log analysis and SPL queries |
| Wireshark | Network packet capture analysis |
| Linux Terminal | File system and code analysis |
| VS Code | PHP/HTML source code review |
| CyberChef | Base64 decoding and data transformation |
| MITRE ATT&CK Navigator | Technique mapping and visualization |
| VirusTotal | IOC reputation checking |

---

