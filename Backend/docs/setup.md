# Cutie-Pie Setup Guide

## Base System
- OS: Any Linux distribution (Debian/Ubuntu-based recommended for apt commands)
- Requirements: Root access for network scanning, 4+ cores and 4GB+ RAM recommended
- Commands:
  ```bash
  sudo apt update && sudo apt full-upgrade -y
  ```

## Scanner Module
### Purpose
Scans IPs for open services (e.g., HTTP) and logs results.

### Dependencies
Install all required packages:
```bash
sudo apt install -y masscan coreutils dnsutils geoip-database geoip-bin whois curl hydra jq
```

Optional (for async scanning):
```bash
pip3 install aiohttp asyncio
```