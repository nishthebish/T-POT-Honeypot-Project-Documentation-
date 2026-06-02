import csv
import json
from collections import defaultdict
from datetime import datetime

CONN_LOG   = "/home/nish_b/zeek-analysis/logs/conn.log"
HTTP_LOG   = "/home/nish_b/zeek-analysis/logs/http.log"
DNS_LOG    = "/home/nish_b/zeek-analysis/logs/dns.log"
WEIRD_LOG  = "/home/nish_b/zeek-analysis/logs/weird.log"
SMB_LOG    = "/home/nish_b/zeek-analysis/logs/smb_mapping.log"
OUTPUT_CSV = "/home/nish_b/zeek-analysis/iocs.csv"
OUTPUT_JSON= "/home/nish_b/zeek-analysis/summary.json"
THRESHOLD  = 1000

def parse_zeek_log(filepath):
    rows = []
    fields = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.rstrip()
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                elif line.startswith("#"):
                    continue
                elif fields:
                    values = line.split("\t")
                    rows.append(dict(zip(fields, values)))
    except FileNotFoundError:
        print(f"[!] Not found: {filepath}")
    return rows

def extract_iocs():
    iocs = []
    summary = {}

    print("[*] Parsing conn.log...")
    conn_rows = parse_zeek_log(CONN_LOG)
    ip_counts = defaultdict(int)
    port_counts = defaultdict(int)
    for row in conn_rows:
        src = row.get("id.orig_h", "")
        dst_port = row.get("id.resp_p", "")
        ip_counts[src] += 1
        port_counts[dst_port] += 1
    scanners = {ip: count for ip, count in ip_counts.items() if count >= THRESHOLD}
    for ip, count in sorted(scanners.items(), key=lambda x: -x[1]):
        iocs.append({"type": "scanner_ip", "indicator": ip, "count": count,
            "description": f"High-volume source: {count} connections",
            "mitre": "T1046 - Network Service Scanning"})
    summary["total_connections"] = len(conn_rows)
    summary["unique_src_ips"] = len(ip_counts)
    summary["scanner_ips"] = len(scanners)
    summary["top_ports"] = sorted(port_counts.items(), key=lambda x: -x[1])[:10]

    print("[*] Parsing http.log...")
    http_rows = parse_zeek_log(HTTP_LOG)
    user_agents = defaultdict(int)
    http_methods = defaultdict(int)
    for row in http_rows:
        user_agents[row.get("user_agent", "-")] += 1
        http_methods[row.get("method", "-")] += 1
    suspicious_agents = [ua for ua in user_agents if any(
        tool in ua.lower() for tool in ["nmap","sqlmap","nikto","masscan","zgrab","python","curl","go-http"])]
    for ua in suspicious_agents:
        iocs.append({"type": "suspicious_user_agent", "indicator": ua, "count": user_agents[ua],
            "description": "Scanning/automation tool user-agent detected",
            "mitre": "T1595 - Active Scanning"})
    summary["http_requests"] = len(http_rows)
    summary["http_methods"] = dict(http_methods)
    summary["suspicious_user_agents"] = suspicious_agents

    print("[*] Parsing dns.log...")
    dns_rows = parse_zeek_log(DNS_LOG)
    dns_queries = defaultdict(int)
    for row in dns_rows:
        dns_queries[row.get("query", "-")] += 1
    summary["dns_queries"] = len(dns_rows)
    summary["unique_domains"] = len(dns_queries)
    summary["top_domains"] = sorted(dns_queries.items(), key=lambda x: -x[1])[:10]

    print("[*] Parsing weird.log...")
    weird_rows = parse_zeek_log(WEIRD_LOG)
    weird_types = defaultdict(int)
    for row in weird_rows:
        name = row.get("name", "-")
        weird_types[name] += 1
        src = row.get("id.orig_h", "")
        if src:
            iocs.append({"type": "anomalous_traffic", "indicator": src, "count": 1,
                "description": f"Zeek weird event: {name}",
                "mitre": "T1036 - Masquerading / Evasion"})
    summary["weird_events"] = dict(weird_types)

    print("[*] Parsing smb_mapping.log...")
    smb_rows = parse_zeek_log(SMB_LOG)
    for row in smb_rows:
        src = row.get("id.orig_h", "")
        share = row.get("path", "-")
        if src:
            iocs.append({"type": "smb_lateral_movement", "indicator": src, "count": 1,
                "description": f"SMB share access: {share}",
                "mitre": "T1021.002 - Remote Services: SMB/Windows Admin Shares"})
    summary["smb_connections"] = len(smb_rows)

    return iocs, summary

def write_outputs(iocs, summary):
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["type","indicator","count","description","mitre"])
        writer.writeheader()
        writer.writerows(iocs)
    print(f"[+] IOCs written to {OUTPUT_CSV} ({len(iocs)} entries)")
    summary["generated"] = datetime.utcnow().isoformat() + "Z"
    summary["total_iocs"] = len(iocs)
    with open(OUTPUT_JSON, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[+] Summary written to {OUTPUT_JSON}")

if __name__ == "__main__":
    print("[*] Starting IOC extraction...")
    iocs, summary = extract_iocs()
    write_outputs(iocs, summary)
    print("[*] Done.")
