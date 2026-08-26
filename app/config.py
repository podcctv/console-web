import os
from pathlib import Path

# Base & Persistent Data Directory
BASE_DIR = Path(__file__).resolve().parent.parent

OPT_BASE = Path("/opt/console-web")
if OPT_BASE.exists() and os.access(OPT_BASE, os.W_OK):
    DATA_DIR = OPT_BASE / "data"
    LOGS_DIR = OPT_BASE / "logs"
else:
    DATA_DIR = BASE_DIR / "data"
    LOGS_DIR = BASE_DIR / "logs"

DATA_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

MONITOR_TARGETS_FILE = DATA_DIR / "targets.json"
UPTIME_FILE = DATA_DIR / "uptime_history.json"
TSDB_DATA_FILE = DATA_DIR / "tsdb_history.json"

# Version & Repository
__version__ = "3.11.0"
GITHUB_REPO_URL = "https://github.com/podcctv/console-web"

# Default ping targets for telemetry (supports IPv4, IPv6, and dual-stack hostnames)
PING_TARGETS = {
    "ping_cloudflare": "one.one.one.one:53",
    "ping_google": "dns.google:53",
    "ping_alidns": "dns.alidns.com:53",
    "ping_ipv6_cf": "[2606:4700:4700::1111]:53",
    "ping_ipv6_google": "[2001:4860:4860::8888]:53",
}

# Supported shell commands
COMMANDS = {
    "ping": lambda target, extra: ["ping", *extra, target] if extra else ["ping", "-c", "4", target],
    "mtr": lambda target, extra: ["mtr", *extra, target] if extra else ["mtr", "-w", "-c", "5", target],
}

# Default target policy list
DEFAULT_TARGETS = [
    {"id": "t1", "name": "Cloudflare DNS (Dual-Stack)", "target": "one.one.one.one:53", "type": "dns", "freq": 30, "threshold_warn": 100, "threshold_crit": 200, "enabled": True},
    {"id": "t2", "name": "Google DNS (Dual-Stack)", "target": "dns.google:53", "type": "dns", "freq": 30, "threshold_warn": 100, "threshold_crit": 200, "enabled": True},
    {"id": "t3", "name": "AliDNS (Dual-Stack)", "target": "dns.alidns.com:53", "type": "dns", "freq": 30, "threshold_warn": 100, "threshold_crit": 200, "enabled": True},
    {"id": "t4", "name": "Cloudflare IPv6 DNS", "target": "[2606:4700:4700::1111]:53", "type": "dns", "freq": 60, "threshold_warn": 150, "threshold_crit": 250, "enabled": True},
    {"id": "t5", "name": "Google IPv6 DNS", "target": "[2001:4860:4860::8888]:53", "type": "dns", "freq": 60, "threshold_warn": 150, "threshold_crit": 250, "enabled": True},
]
