# T-Pot Honeypot Deployment — Google Cloud (GCP)

**Project Owner:** Nishanth Butta  
**Date:** 2025-10-01  
**Stack:** T-Pot (telekom-security/tpotce) · Cowrie · Elastic Stack · Ubuntu 24.04 · Google Cloud Platform  

---

## Summary
I deployed T-Pot on Google Cloud to capture and analyze opportunistic internet attacks. The deployment is isolated in a dedicated VPC, logs are shipped to Elastic, and PCAPs are archived for offline analysis. This repository contains the commands I used, sanitized logs and screenshots, and a monthly reporting template.

---

## What I accomplished
- Deployed T-Pot (hive profile) on Ubuntu 24.04 in GCP.
- Configured firewall rules, rotation of PCAPs, and basic log ingestion into Kibana.
- Captured initial telemetry (SSH brute force attempts, HTTP scanners, SMB probes) and produced a first-month findings template.

---

## Architecture & Environment
- Provider: Google Cloud Platform (GCP)  
- VM: Ubuntu 24.04 LTS, 4 vCPU, 16 GB RAM, 200 GB SSD  
- Network: Dedicated subnet/network tag `tpot`  
- T-Pot version: telekom-security/tpotce (deployed Oct 01 2025)  

**Architecture diagram:** `docs/architecture-diagram.png` (👉 add your diagram here later)  

---

## Quick Status
- Landing page: [https://34.172.240.132:64297](https://34.172.240.132:64297) *(self-signed cert, requires bypass)*  
- Logs: Indexed in Elastic and accessible via Kibana  
- PCAPs: Rotated and archived to `/home/<user>/artifacts/pcap/`  

---

## How to Reproduce (Sanitized)
See `docs/install_steps.md` for the full command log and reproduction steps.  
The key commands are:

```bash
# clone and run the installer as a non-root user
git clone https://github.com/telekom-security/tpotce.git /home/tpotce
cd /home/tpotce
bash install.sh 2>&1 | tee ~/tpot-install.log
sudo reboot
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
