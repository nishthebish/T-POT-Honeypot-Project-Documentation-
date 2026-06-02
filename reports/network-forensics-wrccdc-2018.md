# Network Forensics Analysis — WRCCDC 2018 Competition Traffic

**Analyst:** Nishanth Butta  
**Date:** June 2026  
**Dataset:** WRCCDC 2018 Competition PCAP (`wrccdc.2018-03-23.010014000000000.pcap`, 477MB)  
**Tools Used:** Zeek 8.2.0, Python 3, Wireshark  
**Source:** [Western Regional Collegiate Cyber Defense Competition Archive](https://archive.wrccdc.org/pcaps/2018/)

\---

## Executive Summary

This report documents a network forensics analysis of a 477MB packet capture from the 2018 Western Regional Collegiate Cyber Defense Competition (WRCCDC). The PCAP contains real attack traffic generated against student-defended infrastructure during a live competition, making it representative of opportunistic and targeted network attacks.

Zeek 8.2.0 was used to parse the capture into structured log files. A custom Python IOC extraction script was developed to parse Zeek logs and produce structured CSV and JSON output suitable for threat intelligence consumption.

**Key findings:**

* 395,552 total network connections from 141 unique source IPs
* 9 high-volume scanner IPs identified generating over 1,000 connections each
* Automated scanning tooling detected via HTTP user-agent analysis (`python-requests`, `curl`)
* SMB IPC$ lateral movement activity observed across 3 sessions
* TCP sequence manipulation and invalid HTTP request methods flagged as evasion indicators
* Top targeted services: HTTP (80), DNS (53), HTTPS (443), SMB (445), SSH (22)

\---

## Environment \& Methodology

### Tools

|Tool|Version|Purpose|
|-|-|-|
|Zeek|8.2.0|PCAP parsing, log generation|
|Python|3.x|IOC extraction, CSV/JSON output|
|Wireshark|—|Packet-level session inspection|

### Methodology

1. Obtained public WRCCDC 2018 PCAP from the competition archive
2. Ran Zeek against the full capture to generate structured logs
3. Analyzed conn.log, ssh.log, http.log, dns.log, smb\_mapping.log, and weird.log
4. Developed `ioc\\\_extractor.py` to automate IOC identification and output structured reports
5. Correlated findings across log sources and mapped to MITRE ATT\&CK techniques

\---

## Findings

### 1\. High-Volume Network Scanning (MITRE T1046)

Nine source IPs generated connection volumes exceeding the 1,000-connection threshold, consistent with automated network scanning behavior. The top three sources alone accounted for over 228,000 connections — 57% of total traffic.

|Source IP|Connections|Classification|
|-|-|-|
|10.237.102.3|78,742|High-volume scanner|
|10.147.172.39|78,734|High-volume scanner|
|10.222.236.214|70,708|High-volume scanner|
|10.236.58.83|57,555|High-volume scanner|
|10.192.135.181|44,331|High-volume scanner|
|10.255.81.100|32,625|High-volume scanner|
|10.191.170.154|19,414|High-volume scanner|
|10.131.40.249|6,294|High-volume scanner|
|10.128.0.210|1,109|Moderate scanner|

**Assessment:** The volume and distribution of connections from these IPs is consistent with automated port scanning tools such as Nmap or Masscan operating across the competition subnet. The concentrated activity from a small number of IPs generating the majority of traffic is a classic indicator of botnet-style or coordinated scanning.

**MITRE ATT\&CK:** T1046 — Network Service Discovery

\---

### 2\. Automated HTTP Scanning (MITRE T1595)

Analysis of http.log identified two suspicious user-agent strings indicative of scripted/automated HTTP activity:

|User-Agent|Requests|Assessment|
|-|-|-|
|`python-requests/2.18.4`|42|Automated HTTP scripting|
|`curl/7.54.0`|42|Command-line HTTP automation|

**Assessment:** The presence of `python-requests` and `curl` user-agents indicates automated web reconnaissance rather than browser-based traffic. These tools are commonly used in web enumeration scripts and vulnerability scanning pipelines.

**MITRE ATT\&CK:** T1595 — Active Scanning

\---

### 3\. SMB Lateral Movement (MITRE T1021.002)

Three SMB sessions were observed accessing IPC$ administrative shares across two source hosts:

|Source IP|Target|Share|Session ID|
|-|-|-|-|
|10.128.0.210|10.47.3.218|`\\\\\\\\10.47.3.218\\\\IPC$`|C54N9heJceN7dA6b6|
|10.128.0.210|10.47.3.218|`\\\\\\\\10.47.3.218\\\\IPC$`|C9F26Q25PGggYyGiPi|
|10.128.0.218|10.47.1.218|`\\\\\\\\10.47.1.218\\\\IPC$`|CL6oK14WDklzBKWANg|

**Assessment:** IPC$ (Inter-Process Communication) share access is a known technique used for lateral movement and credential relay attacks. Combined with the NTLM traffic observed in ntlm.log, this pattern is consistent with Pass-the-Hash or SMB relay activity targeting Windows hosts on the competition network.

**MITRE ATT\&CK:** T1021.002 — Remote Services: SMB/Windows Admin Shares

\---

### 4\. Traffic Anomalies \& Evasion Indicators (MITRE T1036)

Zeek's `weird.log` flagged seven anomalous events across four categories:

|Event|Count|Source IP|Assessment|
|-|-|-|-|
|`TCP\\\_ack\\\_underflow\\\_or\\\_misorder`|1|10.47.3.100|TCP sequence manipulation|
|`TCP\\\_seq\\\_underflow\\\_or\\\_misorder`|1|10.47.3.100|TCP sequence manipulation|
|`invalid\\\_http\\\_09\\\_request\\\_method`|4|10.128.0.235|HTTP protocol abuse (OPTIONS)|
|`data\\\_after\\\_reset`|1|10.128.0.252|Data sent post-TCP-RST|

**Assessment:**

* TCP sequence anomalies from `10.47.3.100` may indicate packet injection, IDS evasion techniques, or network stack manipulation
* Repeated `OPTIONS` method requests via HTTP/0.9 from `10.128.0.235` is consistent with web service enumeration (common in tools like Nikto or custom recon scripts)
* `data\\\_after\\\_reset` is a known indicator of covert channel attempts or malformed traffic designed to confuse security monitoring tools

**MITRE ATT\&CK:** T1036 — Masquerading; T1027 — Obfuscated Files or Information

\---

### 5\. Top Targeted Services

|Port|Protocol|Connections|Notes|
|-|-|-|-|
|80|HTTP|1,716|Web service scanning|
|53|DNS|1,367|DNS queries / tunneling recon|
|443|HTTPS|1,297|Encrypted web traffic|
|0|—|1,192|Port 0 probing (OS fingerprinting)|
|22|SSH|102|SSH brute force attempts|
|445|SMB|81|SMB lateral movement|

**Note:** Port 0 connections (1,192 occurrences) are abnormal — legitimate traffic never targets port 0. This is a known OS fingerprinting and IDS evasion technique.

\---

## IOC Summary

21 indicators of compromise were extracted and structured for threat intelligence consumption.

|IOC Type|Count|
|-|-|
|High-volume scanner IPs|9|
|Suspicious HTTP user-agents|2|
|Anomalous traffic events|7|
|SMB lateral movement sources|3|
|**Total**|**21**|

Full IOC listing available in [`iocs.csv`](../iocs.csv)  
Machine-readable summary available in [`summary.json`](../summary.json)

\---

## MITRE ATT\&CK Mapping

|Technique ID|Technique Name|Evidence|
|-|-|-|
|T1046|Network Service Discovery|9 high-volume scanner IPs|
|T1595|Active Scanning|python-requests, curl user-agents|
|T1021.002|SMB/Windows Admin Shares|IPC$ share access from 2 hosts|
|T1036|Masquerading|TCP sequence manipulation, invalid HTTP|
|T1110|Brute Force|SSH connection attempts on port 22|
|T1040|Network Sniffing|Port 0 probing, OS fingerprinting|

\---

## Recommendations

1. **Block or rate-limit high-volume source IPs** at the perimeter — the top 9 scanners should be auto-blocked after exceeding connection thresholds
2. **Alert on IPC$ share access** from non-administrative hosts — SMB lateral movement is a strong indicator of active intrusion
3. **Filter anomalous user-agents** at the web application firewall layer — `python-requests` and `curl` in production web traffic warrant investigation
4. **Monitor for port 0 connections** — any traffic destined for port 0 should be treated as hostile and blocked
5. **Implement TCP sequence validation** — anomalies flagged by Zeek's weird.log indicate potential IDS evasion and should trigger alerts

\---

## Files

```
zeek-analysis/
├── wrccdc.2018-03-23.010014000000000.pcap   # Source capture (477MB)
├── ioc\\\_extractor.py                          # Python IOC extraction script
├── iocs.csv                                  # Structured IOC output (21 entries)
├── summary.json                              # Machine-readable analysis summary
└── logs/
    ├── conn.log       # 395,552 connection records
    ├── http.log       # HTTP request log
    ├── dns.log        # DNS query log
    ├── ssh.log        # SSH session log
    ├── smb\\\_mapping.log # SMB share access log
    ├── ssl.log        # TLS/SSL session metadata
    ├── weird.log      # Anomalous traffic events
    └── ...            # Additional Zeek logs
```

\---

*Analysis conducted as part of a network forensics portfolio project. PCAP sourced from the public WRCCDC 2018 archive. All IP addresses are internal competition network addresses.*



