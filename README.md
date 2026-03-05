# Cutie-Pie Scanner

**Cutie-Pie**, is a live internet scanning tool to dynamically scan exposed devices and classify them.

## Features

- **Dynamic Port Scanning**: Scans for exposed devices with ports defined in a config file, updating in real-time when changes are detected [configurable via frontend].
- **Service Classification**: Automatically creates and manages output files based on port-service mappings (e.g., `http.txt`, `ftp.txt`) and shows the classified output in frontend.
- **Automated Cracking**: Cracks services like ssh, ftp automatically (customizable).
- **Detailed scan for devices**: scans IPs  for detailed and enriched outputs.
- **File Management**: Clears log files when they exceed 500 lines to prevent overflow.

## Prerequisites

- **Operating System**: Any Linux distribution (root access needed for network scanning).
- **Dependencies**:
  - `masscan`
  - `geoiplookup`
  - `dig`
  - `whois`
  - `curl`
  - `nc`
  - `THC-Hydra`
  - `bash` (pre-installed on most Linux distributions).
  - `coreutils` (for `stat`, `grep`, etc.).

  - install all at once: `sudo apt install masscan geoip-bin dnsutils whois curl hydra util-linux coreutils`


- **Permissions**: Run as root (`sudo`) for full network scanning capabilities.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/whxitte/cutie-pie.git
   cd cutie-pie
   ```

2. Install system dependencies if not already present:

   ```bash
   sudo apt update
   sudo apt install masscan geoip-bin dnsutils whois curl hydra util-linux coreutils
   ```

3. Install frontend dependencies:

   ```bash
   cd Frontend
   npm install
   ```

4. Make the scanner scripts executable:

   ```bash
   chmod +x Backend/scanner/*.sh Backend/start.sh
   ```

## Configuration

- **Directory Structure** (auto-detected from the project root):
  - `Backend/config/`: Contains `ports.conf` and `masscan_exclude.conf`.
  - `Backend/logs/scanner/`: Stores output files (e.g., `classified/http.txt`).
- **Environment Variable** (optional):
  - `export SCANNER_BASE=/path/to/cutie-pie/Backend` — Override the auto-detected Backend path.
- **ports.conf**: Define ports and services to scan. Format: `port # service_name` (e.g., `80 # http` or `8080 # http-extra`). Comments start with `#`.
- **masscan_exclude.conf**: Optional file to exclude IP ranges (format per `masscan` docs).

### Example `ports.conf`

```
80 # http
21 # ftp
8080 # http-extra
143 # imap
```

## Usage

1. Start the frontend server:

   ```bash
   cd Frontend
   npm run dev
   ```

2. Start the scanner (in a separate terminal, as root):

   ```bash
   sudo bash Backend/scanner/masscan_live.sh
   ```

3. Modify `ports.conf` to add/remove ports (e.g., add `443 # https`).

4. Watch the console for real-time updates and check output files in `Backend/logs/scanner/classified/`.

### Output Files

- `http.txt`, `ftp.txt`, etc.: Logs IPs with format `IP:PORT:TIMESTAMP` for each service.
- `all.txt`: Aggregates all scan results.

### Controls

- **Interrupt**: Press `Ctrl+C` to stop the script cleanly.
- **Change Detection**: Edit `ports.conf` or touch `config/.ports_changed` to trigger a restart.

## Example Output

```
[INFO] BASE_DIR: /home/user/cutie-pie/Backend
====================================
[INFO] Starting live internet scan at Tue Apr 29 10:19:08 AM EDT 2025 with ports: 80,21
[DEBUG] Running masscan with ports: 80,21
# Masscan 1.3.2 scan initiated Tue Apr 29 14:19:08 2025
Timestamp: 1745936391 Host: 54.188.126.198 () Ports: 80/open/tcp//http//
[DEBUG] Processing IP: ip=54.188.126.198, port=80, timestamp=2025-04-29T14:19:52Z
====================================
[CHANGE] Change detected in Backend/config/ports.conf at Tue Apr 29 10:19:48 AM EDT 2025 - Waiting to process...
====================================
[INFO] Scan completed at Tue Apr 29 10:19:51 AM EDT 2025 - Restarting...
```

## Troubleshooting

- **No IPs Logged**: Ensure `masscan` has internet access and no firewall blocks it. Check `ports.conf` for valid ports.
- **Killed Process**: The `Killed` message is normal when `masscan` is terminated on config changes—ignore it.
- **Permission Denied**: Run with `sudo` or adjust file permissions.
- **Infinite Loop**: If scans restart too quickly, increase the `sleep 3` delay in the script.

## Contributing

Feel free to fork this repo, mahn! Submit pull requests or issues for new features (e.g., rate limiting, additional services) or bug fixes. Hell yeah—let's make it better together!

## License

MIT License—use it, tweak it, share it! Check the `LICENSE` file for details.

## Acknowledgements

- Built with love using `masscan` and Bash wizardry.
- Inspired by the need for a dynamic, real-time scanning tool.

### Test Command
```bash
bash -n Backend/scanner/masscan_live.sh && echo "masscan_live.sh: OK" && bash -n Backend/scanner/enrich.sh && echo "enrich.sh: OK" && bash -n Backend/scanner/crack.sh && echo "crack.sh: OK" && bash -n Backend/start.sh && echo "start.sh: OK"
```