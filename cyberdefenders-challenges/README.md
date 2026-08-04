# CyberDefenders Challenges

## Overview
This section documents blue team investigations completed
on the CyberDefenders platform. Each challenge simulates
a real-world security incident requiring forensic analysis,
threat hunting, and incident documentation following
professional SOC analyst methodology.

---

## Challenges Completed

| # | Challenge | Category | Difficulty | Status |
|---|-----------|----------|------------|--------|
| 1 | BlueSky Ransomware | Network Forensics | Medium | ✅ Complete |
| 2 | GrabThePhisher | Phishing Kit Analysis | Medium | ✅ Complete |

---

## Skills Demonstrated

| Skill | Challenge | Evidence |
|-------|-----------|---------|
| Wireshark PCAP analysis | BlueSky | 4,797 packets analyzed |
| TDS protocol analysis | BlueSky | SQL Server credentials extracted |
| PowerShell payload analysis | BlueSky | checking.ps1, del.ps1 decoded |
| Credential dumping detection | BlueSky | Invoke-PowerDump identified |
| Lateral movement analysis | BlueSky | SMBExec traffic found |
| PHP source code analysis | GrabThePhisher | metamask.php analyzed |
| Telegram C2 identification | GrabThePhisher | Bot token + Chat ID found |
| Threat actor attribution | GrabThePhisher | Developer alias identified |
| IOC extraction | Both | 25+ IOCs documented |
| MITRE ATT&CK mapping | Both | 12 techniques mapped |

---

## Challenge Summaries

### Challenge 01 — BlueSky Ransomware
```
Category:  Network Forensics
Tool:      Wireshark
File:      BlueSkyRansomware.pcap
Packets:   4,797

Attack Summary:
Attacker (87.96.21.84) compromised a Windows SQL
Server (87.96.21.81) using default SA credentials.
Leveraged xp_cmdshell to execute PowerShell payloads,
disabled Windows Defender, established persistence,
dumped NTLM hashes, and performed lateral movement
via SMBExec.

Key Findings:
→ SA credentials: sa / cyb3rd3f3nd3r$
→ xp_cmdshell enabled for OS execution
→ Windows Defender completely disabled
→ NTLM hashes dumped via Invoke-PowerDump
→ Lateral movement via Invoke-SMBExec
→ C2 server: Python SimpleHTTP/0.6

MITRE Techniques: T1046, T1078, T1505.001,
T1059.001, T1562.001, T1053.005,
T1003.002, T1021.002, T1071.001
```

---

### Challenge 02 — GrabThePhisher
```
Category:  Phishing Kit Analysis
Tools:     Linux Terminal, VS Code, CyberChef
Target:    MetaMask cryptocurrency wallet users

Attack Summary:
A MetaMask phishing kit was deployed on a compromised
web server to steal cryptocurrency wallet seed phrases.
The kit used Telegram Bot API for real-time credential
harvesting, collecting victim seed phrases and sending
them instantly to the attacker's Telegram channel.

Key Findings:
→ Wallet targeted: MetaMask (cryptocurrency)
→ Data exfiltration: Telegram Bot API
→ Bot Token: 5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10
→ Chat ID: 5442785564
→ Developer alias: j1j1b1s@m3r0
→ Geo tracking: api.sypexgeo.net API
→ Log storage: /log/log.txt (FILE_APPEND)

MITRE Techniques: T1566, T1056, T1102, T1056.003
```

---

## IOCs Summary

### BlueSky Ransomware IOCs
| IOC | Type |
|-----|------|
| 87.96.21.84 | Attacker IP |
| 87.96.21.81 | Victim IP |
| cyb3rd3f3nd3r$ | Compromised Password |
| sivVZ | Attacker Hostname |
| SimpleHTTP/0.6 Python/3.11.8 | C2 Server |
| /upload.php | Webshell Path |
| Invoke-PowerDump.ps1 | Credential Tool |
| Invoke-SMBExec.ps1 | Lateral Movement Tool |

### GrabThePhisher IOCs
| IOC | Type |
|-----|------|
| 5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10 | Telegram Token |
| 5442785564 | Telegram Chat ID |
| j1j1b1s@m3r0 | Threat Actor Alias |
| api.sypexgeo.net | Geo Tracking API |
| /log/log.txt | Stolen Data Location |

---

## MITRE ATT&CK Coverage

```
BlueSky Ransomware:
├── Reconnaissance:      T1046
├── Initial Access:      T1078, T1190
├── Execution:           T1505.001, T1059.001
├── Persistence:         T1053.005
├── Defense Evasion:     T1562.001
├── Credential Access:   T1003.002
├── Lateral Movement:    T1021.002
└── Command & Control:   T1071.001

GrabThePhisher:
├── Initial Access:      T1566
├── Credential Access:   T1056, T1056.003
└── Command & Control:   T1102
```

---

## How to Use This Repository

Each challenge folder contains a complete investigation
report written in professional SOC analyst style following
the NIST Incident Response framework:

**Preparation** → Understanding the scenario and tools
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

## Why These Challenges

Both challenges were selected to demonstrate
complementary blue team skills:

**BlueSky Ransomware** focuses on network forensics —
analyzing raw packet captures to reconstruct a complete
attack chain from initial SQL Server compromise through
credential dumping and lateral movement.

**GrabThePhisher** focuses on threat actor attribution —
analyzing a live phishing kit's source code to identify
the attacker's infrastructure, tools, and identity through
static code analysis and intelligence gathering.

Together they demonstrate both technical forensics depth
and investigative methodology — core competencies for
any SOC analyst role.

---


