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
__version__ = "3.9.2"
GITHUB_REPO_URL = "https://github.com/podcctv/console-web"

# Default ping targets for telemetry
PING_TARGETS = {
    "ping_cloudflare": "1.1.1.1:53",
    "ping_google": "8.8.8.8:53",
    "ping_cu": "zj-cu-v4.ip.zstaticcdn.com:80",
    "ping_cm": "zj-cm-v4.ip.zstaticcdn.com:80",
    "ping_ct": "zj-ct-v4.ip.zstaticcdn.com:80",
}

# Supported shell commands
COMMANDS = {
    "ping": lambda target, extra: ["ping", *extra, target] if extra else ["ping", "-c", "4", target],
    "mtr": lambda target, extra: ["mtr", *extra, target] if extra else ["mtr", "-w", "-c", "5", target],
}

# Default target policy list
DEFAULT_TARGETS = [
    {"id": "t1", "name": "Zhejiang Unicom CDN", "target": "zj-cu-v4.ip.zstaticcdn.com:80", "type": "tcp", "freq": 30, "threshold_warn": 160, "threshold_crit": 250, "enabled": True},
    {"id": "t2", "name": "Zhejiang Mobile CDN", "target": "zj-cm-v4.ip.zstaticcdn.com:80", "type": "tcp", "freq": 30, "threshold_warn": 160, "threshold_crit": 250, "enabled": True},
    {"id": "t3", "name": "Zhejiang Telecom CDN", "target": "zj-ct-v4.ip.zstaticcdn.com:80", "type": "tcp", "freq": 30, "threshold_warn": 160, "threshold_crit": 250, "enabled": True},
    {"id": "t4", "name": "Cloudflare DNS", "target": "1.1.1.1:53", "type": "dns", "freq": 60, "threshold_warn": 100, "threshold_crit": 200, "enabled": True},
    {"id": "t5", "name": "Google DNS", "target": "8.8.8.8:53", "type": "dns", "freq": 60, "threshold_warn": 100, "threshold_crit": 200, "enabled": True},
]
