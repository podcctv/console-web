import json
import logging
import socket
import subprocess
import time
import threading
import urllib.request
import ipaddress
from datetime import datetime

logger = logging.getLogger(__name__)

_cache_lock = threading.Lock()
_public_ip_cache = {"ip": None, "timestamp": 0}
_isp_cache = {"full": None, "short": None, "timestamp": 0}

ISP_FULL_NAME = None
ISP_SHORT_NAME = None

def tcp_ping(host: str):
    """Attempt TCP socket handshake and measure latency in milliseconds."""
    try:
        if ":" in host:
            host, port = host.rsplit(":", 1)
            port = int(port)
        else:
            port = 80
        start = datetime.now()
        with socket.create_connection((host, port), timeout=2.5):
            end = datetime.now()
        return (end - start).total_seconds() * 1000
    except Exception:
        return None

def icmp_ping(ip: str):
    """Execute ICMP ping command and return latency in milliseconds."""
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if "time=" in line:
                    try:
                        return float(line.split("time=")[1].split(" ")[0])
                    except Exception:
                        pass
    except Exception:
        pass
    return None

def is_private_ip(ip_str: str) -> bool:
    if not ip_str or ip_str in ("N/A", "None", "未检测到"):
        return True
    try:
        clean_ip = ip_str.split()[0].strip()
        ip_obj = ipaddress.ip_address(clean_ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved
    except Exception:
        return True

def get_public_ip() -> str:
    now = time.time()
    with _cache_lock:
        cached = _public_ip_cache["ip"]
        if cached and not is_private_ip(cached) and (now - _public_ip_cache["timestamp"] < 300):
            return cached

    endpoints = [
        "https://api.ipify.org",
        "https://ifconfig.me",
        "https://icanhazip.com"
    ]
    for ep in endpoints:
        try:
            req = urllib.request.Request(ep, headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                pub_ip = resp.read().decode().strip()
                if not is_private_ip(pub_ip):
                    with _cache_lock:
                        _public_ip_cache["ip"] = pub_ip
                        _public_ip_cache["timestamp"] = now
                    return pub_ip
        except Exception:
            continue

    with _cache_lock:
        cached = _public_ip_cache["ip"]
        return cached if (cached and not is_private_ip(cached)) else "未检测到"

def get_isp_info():
    try:
        req = urllib.request.Request("http://ip-api.com/json/?fields=isp", headers={"User-Agent": "console-web/1.6"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            name = json.loads(resp.read().decode()).get("isp")
            if name:
                short = name.split()[0]
                logger.info("Detected ISP: %s (short=%s)", name, short)
                return name, short
            return None, None
    except Exception:
        logger.exception("Failed to fetch ISP info")
        return None, None

def ensure_isp_info():
    global ISP_FULL_NAME, ISP_SHORT_NAME
    now = time.time()
    with _cache_lock:
        if _isp_cache["full"] and (now - _isp_cache["timestamp"] < 600):
            ISP_FULL_NAME = _isp_cache["full"]
            ISP_SHORT_NAME = _isp_cache["short"]
            return

    full, short = get_isp_info()
    with _cache_lock:
        if full or short:
            _isp_cache["full"] = full
            _isp_cache["short"] = short
            _isp_cache["timestamp"] = now
            ISP_FULL_NAME = full
            ISP_SHORT_NAME = short

def query_isp(ip: str):
    if not ip or ip == "127.0.0.1" or ip.startswith("192.168.") or ip.startswith("10."):
        return "局域网/本地"
    try:
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=isp", headers={"User-Agent": "console-web/1.6"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            return json.loads(resp.read().decode()).get("isp")
    except Exception:
        return None

def humanize(seconds: int) -> str:
    seconds = int(seconds)
    years, seconds = divmod(seconds, 31536000)
    months, seconds = divmod(seconds, 2592000)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = []
    if years: parts.append(f"{years}年")
    if months: parts.append(f"{months}月")
    if days: parts.append(f"{days}天")
    if hours: parts.append(f"{hours}小时")
    if minutes: parts.append(f"{minutes}分")
    if seconds or not parts: parts.append(f"{seconds}秒")
    return " ".join(parts)

def humanize_bytes(size: float) -> str:
    if size is None:
        return "N/A"
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}EB"
