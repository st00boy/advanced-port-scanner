#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║       🔍  Advanced Python Port Scanner   ║
║  Features:                               ║
║   • Colorful terminal output             ║
║   • Ping / host availability check       ║
║   • Progress bar during scan             ║
║   • OS & service version detection       ║
╚══════════════════════════════════════════╝
Usage: python3 port_scanner.py
Requirements: pip install tqdm  (optional – falls back gracefully)
"""

import socket
import sys
import platform
import subprocess
import concurrent.futures
import threading
from urllib.parse import urlparse
from datetime import datetime

# ── Optional tqdm progress bar ───────────────────────────────────────────────
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


# ─────────────────────────────────────────────────────────────────────────────
# ANSI Color helpers
# ─────────────────────────────────────────────────────────────────────────────
def _supports_color() -> bool:
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOR = _supports_color()


class C:
    RESET   = "\033[0m"  if USE_COLOR else ""
    BOLD    = "\033[1m"  if USE_COLOR else ""
    DIM     = "\033[2m"  if USE_COLOR else ""
    RED     = "\033[91m" if USE_COLOR else ""
    GREEN   = "\033[92m" if USE_COLOR else ""
    YELLOW  = "\033[93m" if USE_COLOR else ""
    BLUE    = "\033[94m" if USE_COLOR else ""
    CYAN    = "\033[96m" if USE_COLOR else ""
    WHITE   = "\033[97m" if USE_COLOR else ""
    GRAY    = "\033[90m" if USE_COLOR else ""
    MAGENTA = "\033[95m" if USE_COLOR else ""


def color(text: str, *codes: str) -> str:
    return "".join(codes) + text + C.RESET


# ─────────────────────────────────────────────────────────────────────────────
# Common ports → (service label, protocol hint)
# ─────────────────────────────────────────────────────────────────────────────
COMMON_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Dev",
    27017: "MongoDB",
}

HIGH_RISK_PORTS   = {21, 23, 445, 3389}
MEDIUM_RISK_PORTS = {25, 110, 143, 3306, 5432, 6379, 27017}


# ─────────────────────────────────────────────────────────────────────────────
# URL / hostname parsing
# ─────────────────────────────────────────────────────────────────────────────
def extract_hostname(user_input: str) -> str:
    raw = user_input.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        hostname = parsed.hostname or parsed.netloc
    else:
        hostname = raw.split("/")[0]
    return hostname.split(":")[0].lower()


def resolve_host(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve '{hostname}': {e}")


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE 1 – Ping / host availability check
# ─────────────────────────────────────────────────────────────────────────────
def ping_host(ip: str) -> tuple[bool, float]:
    """
    Ping via OS command. Returns (is_alive, avg_rtt_ms).
    Falls back to TCP probe if ICMP is blocked.
    """
    system       = platform.system()
    count_flag   = "-n" if system == "Windows" else "-c"
    timeout_flag = "-w" if system == "Windows" else "-W"
    timeout_val  = "1000" if system == "Windows" else "1"

    try:
        result = subprocess.run(
            ["ping", count_flag, "2", timeout_flag, timeout_val, ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6,
        )
        output = result.stdout.decode(errors="replace")
        alive  = result.returncode == 0
        rtt    = 0.0

        # Parse average RTT
        for line in output.splitlines():
            line_l = line.lower()
            if "avg" in line_l or "average" in line_l:
                nums = [s for s in line.replace("/", " ").split() if _is_float(s)]
                if nums:
                    try:
                        rtt = float(nums[0])
                    except ValueError:
                        pass
                break

        return alive, rtt

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # TCP fallback
    for port in (80, 443, 22):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                t0 = datetime.now()
                if s.connect_ex((ip, port)) == 0:
                    rtt = (datetime.now() - t0).total_seconds() * 1000
                    return True, rtt
        except Exception:
            continue
    return False, 0.0


def _is_float(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE 2 – OS fingerprinting via TTL
# ─────────────────────────────────────────────────────────────────────────────
def guess_os_from_ttl(ip: str) -> str:
    system       = platform.system()
    count_flag   = "-n" if system == "Windows" else "-c"
    timeout_flag = "-w" if system == "Windows" else "-W"
    timeout_val  = "1000" if system == "Windows" else "1"

    try:
        result = subprocess.run(
            ["ping", count_flag, "1", timeout_flag, timeout_val, ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4,
        )
        output = result.stdout.decode(errors="replace").lower()
        for chunk in output.split():
            if "ttl=" in chunk:
                try:
                    ttl = int(chunk.split("=")[1])
                    if ttl <= 64:
                        return f"Linux / macOS  (TTL={ttl})"
                    elif ttl <= 128:
                        return f"Windows        (TTL={ttl})"
                    else:
                        return f"Network device (TTL={ttl})"
                except ValueError:
                    pass
    except Exception:
        pass
    return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE 3 – Banner grabbing + service/version detection
# ─────────────────────────────────────────────────────────────────────────────
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
_WAIT_FOR_BANNER = {21, 25, 110, 143, 3306, 6379}   # server speaks first


def grab_banner(ip: str, port: int, hostname: str = "", timeout: float = 2.0) -> str:
    if port in (443, 8443):
        return "(SSL/TLS – use openssl for details)"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            if port in (80, 8080, 8888):
                probe = _HTTP_PROBE.replace(b"{host}", (hostname or ip).encode())
                s.sendall(probe)
            elif port not in _WAIT_FOR_BANNER:
                s.sendall(b"\r\n")

            raw = s.recv(512).decode(errors="replace").strip()
            return raw.split("\n")[0][:100].strip()
    except Exception:
        return ""


def detect_service_version(banner: str, port: int) -> tuple[str, str]:
    """Return (service_label, version_string) parsed from banner."""
    b = banner.lower()

    if "ssh" in b:
        parts = banner.split("-")
        version = parts[2].strip() if len(parts) >= 3 else banner.strip()
        return "SSH", version

    if "server:" in b:
        for line in banner.splitlines():
            if line.lower().startswith("server:"):
                return "HTTP", line.split(":", 1)[1].strip()

    if "vsftpd" in b or "pure-ftpd" in b or "filezilla" in b or ("ftp" in b and port == 21):
        return "FTP", banner.split("\n")[0].strip()

    if "postfix" in b or "sendmail" in b or "esmtp" in b or ("smtp" in b and port == 25):
        return "SMTP", banner.split("\n")[0].strip()

    if port == 3306 and banner:
        # MySQL binary handshake – extract printable version fragment
        ver = "".join(c for c in banner if c.isdigit() or c == ".")
        return "MySQL", f"v{ver[:10]}" if ver else "MySQL"

    if "+pong" in b or "redis_version" in b:
        return "Redis", banner.strip()

    return "", ""


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE 4 – Concurrent scan with progress bar
# ─────────────────────────────────────────────────────────────────────────────
def scan_ports(
    ip: str,
    hostname: str,
    ports: list[int],
    max_workers: int = 150,
    timeout: float = 1.0,
) -> list[dict]:
    open_ports: list[dict] = []
    lock  = threading.Lock()
    done  = 0
    total = len(ports)

    # ── Progress bar (tqdm or built-in) ──────────────────
    if HAS_TQDM:
        bar = tqdm(
            total=total,
            desc=color("  Scanning", C.CYAN, C.BOLD),
            unit="port",
            ncols=65,
            bar_format="{desc} {bar} {n_fmt}/{total_fmt}  [{elapsed}<{remaining}]",
            colour="cyan",
        )
    else:
        bar = None
        _last: list[int] = [-1]

    def _update():
        nonlocal done
        done += 1
        if bar:
            bar.update(1)
        else:
            pct = int(done / total * 40)
            if pct != _last[0]:
                _last[0] = pct
                filled = color("█" * pct, C.CYAN)
                empty  = color("░" * (40 - pct), C.GRAY)
                perc   = color(f"{int(done / total * 100):3d}%", C.BOLD, C.WHITE)
                print(f"\r  {filled}{empty}  {perc}  ({done}/{total})",
                      end="", flush=True)

    def _check(port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                is_open = s.connect_ex((ip, port)) == 0
        except Exception:
            is_open = False

        if is_open:
            banner      = grab_banner(ip, port, hostname)
            svc, ver    = detect_service_version(banner, port)
            service     = svc or COMMON_PORTS.get(port, "Unknown")
            with lock:
                open_ports.append({
                    "port":    port,
                    "service": service,
                    "version": ver,
                    "banner":  banner,
                })
        _update()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        fs = [ex.submit(_check, p) for p in ports]
        try:
            concurrent.futures.wait(fs)
        except KeyboardInterrupt:
            for f in fs:
                f.cancel()
            raise

    if bar:
        bar.close()
    else:
        print()   # newline after inline bar

    return sorted(open_ports, key=lambda x: x["port"])


# ─────────────────────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────────────────────
def port_color(port: int) -> str:
    if port in HIGH_RISK_PORTS:
        return C.RED
    if port in MEDIUM_RISK_PORTS:
        return C.YELLOW
    return C.GREEN


def print_header():
    w = 62
    border = color("═" * w, C.CYAN, C.BOLD)
    print(f"\n{color('╔', C.CYAN, C.BOLD)}{border}{color('╗', C.CYAN, C.BOLD)}")
    title = "🔍  Advanced Port Scanner"
    pad   = (w - len(title)) // 2
    inner = " " * pad + title + " " * (w - pad - len(title))
    print(f"{color('║', C.CYAN, C.BOLD)}{color(inner, C.CYAN, C.BOLD)}{color('║', C.CYAN, C.BOLD)}")
    print(f"{color('╚', C.CYAN, C.BOLD)}{border}{color('╝', C.CYAN, C.BOLD)}")


def print_ping_result(hostname: str, ip: str, alive: bool, rtt: float, os_guess: str):
    status = (
        color("✔  ONLINE",  C.GREEN, C.BOLD) if alive
        else color("✘  OFFLINE / PING BLOCKED", C.RED, C.BOLD)
    )
    rtt_str = f"   {color(f'RTT ≈ {rtt:.1f} ms', C.GRAY)}" if rtt > 0 else ""
    print(f"\n  {color('HOST :', C.BOLD)} {color(hostname, C.CYAN)}  {color('(' + ip + ')', C.YELLOW)}")
    print(f"  {color('PING :', C.BOLD)} {status}{rtt_str}")
    print(f"  {color('OS   :', C.BOLD)} {color(os_guess, C.MAGENTA)}")


def print_results(hostname: str, ip: str, open_ports: list[dict], elapsed: float):
    w = 62
    print()
    print(color("─" * w, C.CYAN))
    print(
        f"  {color('Target  :', C.BOLD)} {color(hostname, C.CYAN)}\n"
        f"  {color('IP      :', C.BOLD)} {color(ip, C.YELLOW)}\n"
        f"  {color('Time    :', C.BOLD)} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  {color('Duration:', C.BOLD)} {elapsed:.2f}s"
    )
    print(color("─" * w, C.CYAN))

    if not open_ports:
        print(color("  ✗  No open ports found in the scanned range.\n", C.RED))
        return

    # Column header
    print(color(f"  {'PORT':<9}{'SERVICE':<15}{'VERSION / BANNER'}", C.BOLD, C.WHITE))
    print(color("  " + "─" * (w - 2), C.GRAY))

    for e in open_ports:
        pc     = port_color(e["port"])
        port_s = color(f"{e['port']:<9}", pc, C.BOLD)
        svc_s  = color(f"{e['service']:<15}", C.WHITE, C.BOLD)

        info = e.get("version") or e.get("banner") or ""
        if len(info) > 50:
            info = info[:47] + "…"
        info_s = color(info, C.GRAY)

        risk = ""
        if e["port"] in HIGH_RISK_PORTS:
            risk = color("  ⚠ HIGH RISK", C.RED, C.BOLD)
        elif e["port"] in MEDIUM_RISK_PORTS:
            risk = color("  ⚡ REVIEW", C.YELLOW)

        print(f"  {port_s}{svc_s}{info_s}{risk}")

    print(color("─" * w, C.CYAN))
    print(f"  ✔  {color(str(len(open_ports)), C.GREEN, C.BOLD)} open port(s) found.\n")

    # Legend
    if any(e["port"] in HIGH_RISK_PORTS | MEDIUM_RISK_PORTS for e in open_ports):
        print(color("  Risk legend:", C.BOLD))
        print(f"    {color('⚠ HIGH RISK', C.RED, C.BOLD)}  – Insecure / legacy protocol exposed")
        print(f"    {color('⚡ REVIEW   ', C.YELLOW)}  – Database / service; review firewall rules")
        print()


def get_port_range(choice: str) -> list[int]:
    if choice == "1":
        return sorted(COMMON_PORTS.keys())
    elif choice == "2":
        return list(range(1, 1025))
    elif choice == "3":
        return list(range(1, 10001))
    elif choice == "4":
        raw = input(color("  Enter ports/ranges (e.g. 22,80,443,8000-8100): ", C.CYAN)).strip()
        ports: set[int] = set()
        for part in raw.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    a, b = part.split("-", 1)
                    ports.update(range(int(a), int(b) + 1))
                except ValueError:
                    print(color(f"  ⚠ Skipping invalid range: {part}", C.YELLOW))
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    print(color(f"  ⚠ Skipping invalid port: {part}", C.YELLOW))
        return sorted(ports)
    else:
        print(color("  Invalid choice – using common ports.", C.YELLOW))
        return sorted(COMMON_PORTS.keys())


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print_header()

    if not HAS_TQDM:
        print(color(
            "\n  💡 Tip: run  pip install tqdm  for a nicer progress bar",
            C.GRAY
        ))

    # ── 1. Get target ──────────────────────────────────────────────────────
    target_input = input(color("\n  Enter website / URL:\n  > ", C.CYAN, C.BOLD)).strip()
    if not target_input:
        print(color("  No input provided. Exiting.", C.RED))
        sys.exit(1)

    try:
        hostname = extract_hostname(target_input)
        print(color(f"\n  Resolving {hostname} …", C.GRAY))
        ip = resolve_host(hostname)
    except ValueError as e:
        print(color(f"\n  ✗ {e}", C.RED))
        sys.exit(1)

    # ── 2. Ping + OS fingerprint ───────────────────────────────────────────
    print(color("  Pinging host …", C.GRAY))
    alive, rtt = ping_host(ip)
    os_guess   = guess_os_from_ttl(ip)
    print_ping_result(hostname, ip, alive, rtt, os_guess)

    if not alive:
        cont = input(color(
            "\n  Host may be offline or blocking ICMP. Scan anyway? [y/N]: ",
            C.YELLOW
        )).strip().lower()
        if cont != "y":
            print(color("  Scan cancelled.", C.RED))
            sys.exit(0)

    # ── 3. Choose scan mode ────────────────────────────────────────────────
    print(color("\n  Select scan mode:", C.BOLD, C.WHITE))
    modes = [
        ("1", "Common ports only ", f"fast, {len(COMMON_PORTS)} ports"),
        ("2", "Well-known range  ", "ports 1 – 1 024"),
        ("3", "Extended range    ", "ports 1 – 10 000"),
        ("4", "Custom ports      ", "e.g. 22,80,8000-8100"),
    ]
    for key, label, hint in modes:
        print(f"   {color('[' + key + ']', C.CYAN)}  {label}  {color(hint, C.GRAY)}")

    choice = input(color("  > ", C.CYAN, C.BOLD)).strip()
    ports  = get_port_range(choice)

    # ── 4. Scan ────────────────────────────────────────────────────────────
    print(color(
        f"\n  Scanning {len(ports)} port(s) on "
        f"{color(hostname, C.CYAN)} ({color(ip, C.YELLOW)}) …\n",
        C.WHITE
    ))

    start = datetime.now()
    try:
        open_ports = scan_ports(ip, hostname, ports, max_workers=150, timeout=1.0)
    except KeyboardInterrupt:
        print(color("\n\n  Scan interrupted by user.", C.RED))
        sys.exit(0)

    elapsed = (datetime.now() - start).total_seconds()
    print_results(hostname, ip, open_ports, elapsed)


if __name__ == "__main__":
    main()
