# T-Pot Honeypot Deployment — Google Cloud (GCP)

**Project Owner:** Nishanth Butta  
**Date:** October 1, 2025  
**Stack:** T-Pot (telekom-security/tpotce) · Cowrie · Elastic Stack · Ubuntu 24.04 · Google Cloud Platform  

---

## Summary
This project documents the deployment of a T-Pot honeypot on Google Cloud to capture and analyze opportunistic internet attacks. The environment is isolated in a dedicated cloud network, logs are indexed in the Elastic Stack, and packet captures (PCAPs) are archived for offline analysis.

This repository includes sanitized setup steps, screenshots, and a reporting template to support reproducibility and analysis.

---

## What I Accomplished
- Deployed a T-Pot honeypot (Hive profile) on Ubuntu 24.04 in Google Cloud  
- Configured firewall rules and network isolation to safely expose honeypot services  
- Captured live attacker telemetry including SSH brute force attempts, HTTP scans, and SMB probes  
- Documented the deployment process and created a structured reporting template for ongoing analysis  

---

## Architecture & Environment
- **Cloud Provider:** Google Cloud Platform (GCP)  
- **Virtual Machine:** Ubuntu 24.04 LTS, 4 vCPU, 16 GB RAM, 200 GB SSD  
- **Network:** Dedicated subnet with network tag `tpot`  
- **Honeypot Platform:** T-Pot (telekom-security/tpotce)  
- **Deployment Date:** October 1, 2025  

*Architecture diagram:* `docs/architecture-diagram.png` (to be added)

---

## Quick Status
- **T-Pot Dashboard:** https://34.172.240.132:64297  
  *(Self-signed certificate — browser security warning expected)*  
- **Logs:** Indexed in Elastic and accessible via Kibana dashboards  
- **PCAP Storage:** `/home/<user>/artifacts/pcap/` (rotated and archived)  

---

## How to Reproduce (Sanitized)
Detailed setup instructions are available in `docs/install_steps.md`.  
Key commands used during deployment:

```bash
# Clone and run the installer as a non-root user
git clone https://github.com/telekom-security/tpotce.git /home/tpotce
cd /home/tpotce
bash install.sh 2>&1 | tee ~/tpot-install.log
sudo reboot
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
