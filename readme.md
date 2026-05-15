🔍 Advanced Python Port Scanner
A fast, colorful, and feature-rich terminal-based port scanner built in Python. Scans hosts for open ports with service detection, OS fingerprinting, banner grabbing, and a live progress bar — all with zero mandatory dependencies.

✨ Features

Host Availability Check — Pings the target before scanning; falls back to TCP probe if ICMP is blocked
OS Fingerprinting — Guesses the target OS (Linux/macOS/Windows/Network device) from TTL values
Service & Version Detection — Identifies services like SSH, HTTP, FTP, MySQL, Redis, and more from banners
Banner Grabbing — Sends probes to open ports and captures service responses
Concurrent Scanning — Uses a thread pool (up to 150 workers) for high-speed scans
Live Progress Bar — Real-time scan progress via tqdm (with a built-in fallback if not installed)
Risk Highlighting — Flags high-risk ports (FTP, Telnet, SMB, RDP) and services worth reviewing
Flexible Scan Modes — Common ports, well-known range, extended range, or fully custom port lists
Colorful Terminal Output — ANSI color support with automatic Windows compatibility


📋 Requirements

Python 3.9+
tqdm (optional — for a nicer progress bar)


🚀 Installation
bash# Clone the repository
git clone https://github.com/st00boy/advanced-port-scanner.git
cd advanced-port-scanner

# (Optional) Install tqdm for enhanced progress bar
pip install tqdm
No other dependencies required — everything else uses the Python standard library.

🖥️ Usage
bashpython3 port_scanner.py
The tool will interactively prompt you for:

Target — Enter a hostname, URL, or IP address (e.g. example.com, https://example.com, 192.168.1.1)
Scan Mode — Choose from four options:

OptionModeDescription1Common portsFast scan of 18 well-known ports2Well-known rangePorts 1 – 1,0243Extended rangePorts 1 – 10,0004Custome.g. 22,80,443,8000-8100

📸 Example Output
╔══════════════════════════════════════════════════════════════╗
║                   🔍  Advanced Port Scanner                  ║
╚══════════════════════════════════════════════════════════════╝

  Enter website / URL:
  > example.com

  Resolving example.com …
  HOST : example.com  (93.184.216.34)
  PING : ✔  ONLINE   RTT ≈ 12.3 ms
  OS   : Linux / macOS  (TTL=56)

  Scanning 18 port(s) on example.com (93.184.216.34) …

  PORT     SERVICE        VERSION / BANNER
  ──────────────────────────────────────────────────────────────
  80       HTTP           Apache/2.4.41 (Ubuntu)
  443      HTTPS          (SSL/TLS – use openssl for details)
  22       SSH            OpenSSH_8.2p1              ⚠ HIGH RISK
  ──────────────────────────────────────────────────────────────
  ✔  3 open port(s) found.

⚠️ Risk Legend
IndicatorMeaning⚠ HIGH RISKInsecure or legacy protocol exposed (FTP, Telnet, SMB, RDP)⚡ REVIEWDatabase or sensitive service; check your firewall rules

🗂️ Detected Services
The scanner has built-in detection for:
SSH · HTTP/HTTPS · FTP · SMTP · Telnet · DNS · POP3 · IMAP · SMB · MySQL · PostgreSQL · Redis · MongoDB · RDP

⚖️ Legal Disclaimer

This tool is intended for authorized use only.
Only scan hosts and networks that you own or have explicit permission to test.
Unauthorized port scanning may be illegal in your jurisdiction.
The author is not responsible for any misuse of this tool.


📄 License
MIT License — see LICENSE for details.

🙌 Contributing
Pull requests are welcome! If you find a bug or have a feature suggestion, please open an issue.
