# Splunk Investigations

## Overview
This section documents hands-on Splunk SIEM investigations
completed on TryHackMe. Each investigation demonstrates
real SOC analyst workflow using SPL queries to analyze
web traffic and firewall logs, identify attackers, and
reconstruct full attack chains.

---

## Investigations Completed

| # | Investigation | Platform | Difficulty | Status |
|---|---------------|----------|------------|--------|
| 1 | Investigating with Splunk | TryHackMe | Medium | ✅ Complete |

---

## Key Skills Demonstrated

| Skill | Evidence |
|-------|---------|
| Splunk SPL queries | 8 custom queries written |
| Web traffic analysis | 17,172 events analyzed |
| Attacker identification | IP 198.51.100.55 isolated |
| Attack tool detection | sqlmap, Havij, zgrab, Webshell Runner |
| LFI exploitation analysis | /etc/passwd access confirmed |
| C2 communication detection | 285 beacon connections found |
| Data exfiltration quantification | 126,167 bytes measured |
| MITRE ATT&CK mapping | 8 techniques mapped |

---

## Tools Used

```
Splunk Enterprise 8.2
SPL (Search Processing Language)
MITRE ATT&CK Framework
```

---

## Investigation Summary

### Investigating with Splunk
```
Target:    tbfc.thm web server
Attacker:  198.51.100.55
Events:    17,172 web traffic logs
           285 firewall C2 events

Attack Chain:
Recon → SQLi → LFI → Webshell → C2 → Exfil

Findings:
→ Attacker used 8 malicious tools
→ /etc/passwd successfully read (LFI)
→ Webshell deployed via /upload.php
→ 126,167 bytes exfiltrated
→ 8 MITRE ATT&CK techniques mapped
```

---

