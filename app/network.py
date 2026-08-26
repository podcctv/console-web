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
_public_ip_cache = {"ip": None, "ipv4": None, "ipv6": None, "timestamp": 0}
_isp_cache = {"full": None, "short": None, "timestamp": 0}

ISP_FULL_NAME = None
ISP_SHORT_NAME = None

def parse_host_port(host_str: str, default_port: int = 80) -> tuple:
    """Robustly parse host and port from strings, supporting IPv4, hostnames, and bracketed/raw IPv6."""
    if not host_str:
        return "127.0.0.1", default_port
    host_str = host_str.strip()

    # Case 1: Bracketed IPv6, e.g. [2606:4700::1111]:53 or [2606:4700::1111]
    if host_str.startswith("["):
        if "]:" in host_str:
            h, p = host_str.split("]:", 1)
            clean_host = h.lstrip("[")
            try:
                port = int(p)
            except ValueError:
                port = default_port
            return clean_host, port
        else:
            return host_str.strip("[]"), default_port

    # Case 2: Unbracketed IPv6 (contains 2 or more colons)
    if host_str.count(":") >= 2:
        return host_str, default_port

    # Case 3: Host with port (IPv4:port or domain:port)
    if ":" in host_str:
        parts = host_str.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1])
        return parts[0], default_port

    return host_str, default_port

def tcp_ping(host: str, timeout: float = 2.5):
    """Attempt TCP socket handshake and measure latency in milliseconds (supports IPv4, IPv6, hostnames)."""
    try:
        clean_host, port = parse_host_port(host, default_port=80)
        start = datetime.now()
        with socket.create_connection((clean_host, port), timeout=timeout):
            end = datetime.now()
        return (end - start).total_seconds() * 1000
    except Exception:
        return None

def icmp_ping(ip: str):
    """Execute ICMP ping command and return latency in milliseconds, automatically supporting IPv4 and IPv6."""
    try:
        clean_host, _ = parse_host_port(ip)
        cmd = ["ping", "-c", "1", "-W", "2", clean_host]
        if ":" in clean_host:
            # Check if ping -6 is needed or if standard ping handles IPv6
            cmd = ["ping", "-6", "-c", "1", "-W", "2", clean_host]

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0 and ":" in clean_host:
            # Fallback to standard ping without -6 flag
            proc = subprocess.run(
                ["ping", "-c", "1", "-W", "2", clean_host],
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
    """Check if an IP string (IPv4 or IPv6) is private, loopback, or reserved."""
    if not ip_str or ip_str in ("N/A", "None", "未检测到"):
        return True
    try:
        clean_ip = ip_str.strip().strip("[]").split()[0].strip()
        ip_obj = ipaddress.ip_address(clean_ip)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        )
    except Exception:
        return True

def is_warp_or_shared_egress_ip(ip_str: str) -> bool:
    """Check if an IPv4 is a Cloudflare WARP or shared NAT64 egress IP that cannot receive inbound connections."""
    if not ip_str:
        return False
    try:
        clean_ip = ip_str.strip().strip("[]").split()[0].strip()
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.version != 4:
            return False
        # Known Cloudflare WARP and shared CDN proxy egress IPv4 ranges
        warp_networks = [
            ipaddress.ip_network("104.28.0.0/15"),    # Cloudflare WARP egress
            ipaddress.ip_network("104.16.0.0/12"),    # Cloudflare CDN
            ipaddress.ip_network("162.158.0.0/15"),   # Cloudflare
            ipaddress.ip_network("172.64.0.0/13"),    # Cloudflare
            ipaddress.ip_network("198.41.128.0/17"),  # Cloudflare
            ipaddress.ip_network("108.162.192.0/18"), # Cloudflare
            ipaddress.ip_network("141.101.64.0/18"),  # Cloudflare
            ipaddress.ip_network("190.93.240.0/20"),  # Cloudflare
            ipaddress.ip_network("188.114.96.0/20"),  # Cloudflare
            ipaddress.ip_network("197.234.240.0/22"), # Cloudflare
            ipaddress.ip_network("173.245.48.0/20"),  # Cloudflare
            ipaddress.ip_network("103.21.244.0/22"),  # Cloudflare
            ipaddress.ip_network("103.22.200.0/22"),  # Cloudflare
            ipaddress.ip_network("103.31.4.0/22"),    # Cloudflare
            ipaddress.ip_network("131.0.72.0/22"),    # Cloudflare
        ]
        for net in warp_networks:
            if ip_obj in net:
                return True
    except Exception:
        pass
    return False

def get_public_ipv4() -> str:
    """Query external endpoints strictly for public IPv4 address."""
    endpoints = [
        "https://api.ipify.org",
        "https://v4.ident.me",
        "https://4.icanhazip.com"
    ]
    for ep in endpoints:
        try:
            req = urllib.request.Request(ep, headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                v4 = resp.read().decode().strip()
                if ":" not in v4 and not is_private_ip(v4):
                    return v4
        except Exception:
            continue
    return None

def get_public_ipv6() -> str:
    """Query external endpoints strictly for public IPv6 address."""
    endpoints = [
        "https://api6.ipify.org",
        "https://v6.ident.me",
        "https://6.icanhazip.com"
    ]
    for ep in endpoints:
        try:
            req = urllib.request.Request(ep, headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                v6 = resp.read().decode().strip()
                if ":" in v6 and not is_private_ip(v6):
                    return v6
        except Exception:
            continue

    # Fallback to local default route for IPv6 (if external IPv6 endpoint times out)
    try:
        proc = subprocess.run(
            ["ip", "-6", "route", "get", "2001:4860:4860::8888"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2
        )
        if proc.returncode == 0:
            tokens = proc.stdout.split()
            if "src" in tokens:
                src_ip = tokens[tokens.index("src") + 1]
                if ":" in src_ip and not is_private_ip(src_ip):
                    return src_ip
    except Exception:
        pass

    return None

def get_network_stack_info() -> dict:
    """Detect public IPv4, public IPv6, recognize WARP egress, and classify network stack."""
    now = time.time()
    with _cache_lock:
        if _public_ip_cache["timestamp"] > 0 and (now - _public_ip_cache["timestamp"] < 300):
            v4 = _public_ip_cache.get("ipv4")
            v6 = _public_ip_cache.get("ipv6")
            ip = _public_ip_cache.get("ip")
            warp = _public_ip_cache.get("is_warp", False)
            stack_type = _public_ip_cache.get("stack_type")
            stack_label = _public_ip_cache.get("stack_label")
            return {
                "ipv4": v4,
                "ipv6": v6,
                "primary_ip": ip,
                "is_warp": warp,
                "stack_type": stack_type,
                "stack_label": stack_label
            }

    v4 = get_public_ipv4()
    v6 = get_public_ipv6()
    is_warp = is_warp_or_shared_egress_ip(v4) if v4 else False

    # Classification logic:
    # 1. Dual Stack: Real public IPv4 (non-WARP) + Public IPv6
    if v4 and not is_warp and v6:
        stack_type = "dual"
        stack_label = "IPv4/IPv6 双栈 (Dual-Stack)"
        primary_ip = v4
    # 2. IPv6-Only with WARP Outbound: Public IPv6 + Cloudflare WARP IPv4
    elif v6 and is_warp:
        stack_type = "ipv6_only_warp"
        stack_label = "纯 IPv6 (IPv6-Only) + WARP 出口"
        primary_ip = v6
    # 3. Pure IPv6 (IPv6-Only): Public IPv6 + No IPv4
    elif v6 and not v4:
        stack_type = "ipv6_only"
        stack_label = "纯 IPv6 (IPv6-Only 纯v6)"
        primary_ip = v6
    # 4. Pure IPv4 (IPv4-Only): Real public IPv4 + No IPv6
    elif v4 and not is_warp and not v6:
        stack_type = "ipv4_only"
        stack_label = "纯 IPv4 (IPv4-Only)"
        primary_ip = v4
    # 5. WARP Only without IPv6
    elif v4 and is_warp and not v6:
        stack_type = "warp_only"
        stack_label = "WARP 出口环境 (无公网入站 IP)"
        primary_ip = v4
    else:
        stack_type = "local"
        stack_label = "内网 / 本地环境"
        primary_ip = v4 or v6 or "未检测到"

    with _cache_lock:
        _public_ip_cache["ipv4"] = v4
        _public_ip_cache["ipv6"] = v6
        _public_ip_cache["ip"] = primary_ip
        _public_ip_cache["is_warp"] = is_warp
        _public_ip_cache["stack_type"] = stack_type
        _public_ip_cache["stack_label"] = stack_label
        _public_ip_cache["timestamp"] = now

    return {
        "ipv4": v4,
        "ipv6": v6,
        "primary_ip": primary_ip,
        "is_warp": is_warp,
        "stack_type": stack_type,
        "stack_label": stack_label
    }

def get_public_ip() -> str:
    """Return primary public inbound IP (IPv6 if IPv4 is WARP/absent, IPv4 if genuine dual-stack)."""
    stack = get_network_stack_info()
    return stack["primary_ip"]

def get_isp_info(ip: str = None):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=isp" if ip else "http://ip-api.com/json/?fields=isp"
        req = urllib.request.Request(url, headers={"User-Agent": "console-web/3.11"})
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

    pub_ip = get_public_ip()
    target_ip = None if is_private_ip(pub_ip) else pub_ip
    full, short = get_isp_info(target_ip)
    with _cache_lock:
        if full or short:
            _isp_cache["full"] = full
            _isp_cache["short"] = short
            _isp_cache["timestamp"] = now
            ISP_FULL_NAME = full
            ISP_SHORT_NAME = short

def query_isp(ip: str):
    if not ip or is_private_ip(ip):
        return "局域网/本地"
    try:
        clean_ip = ip.strip().strip("[]")
        req = urllib.request.Request(f"http://ip-api.com/json/{clean_ip}?fields=isp", headers={"User-Agent": "console-web/3.11"})
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

_node_id_cache = {"node_id": None, "timestamp": 0}

def get_auto_node_id(ip: str = None) -> str:
    """Generate a realistic, professional Node ID based on server public IP (IPv4/IPv6) geolocation and ISP."""
    now = time.time()
    with _cache_lock:
        if _node_id_cache["node_id"] and (now - _node_id_cache["timestamp"] < 3600):
            return _node_id_cache["node_id"]

    if not ip or is_private_ip(ip):
        ip = get_public_ip()

    if is_private_ip(ip):
        return "local-dev-vps-01"

    clean_ip = ip.strip().strip("[]")
    node_id = "v6-node-01" if ":" in clean_ip else "fra1-vps-01"

    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{clean_ip}?fields=countryCode,city,isp",
            headers={"User-Agent": "console-web/3.11"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            country = (data.get("countryCode") or "US").upper()
            city = (data.get("city") or "").lower()
            isp = (data.get("isp") or "").lower()

            city_code = country.lower()
            if "frankfurt" in city: city_code = "fra"
            elif "hong kong" in city or country == "HK": city_code = "hkg"
            elif "tokyo" in city or "osaka" in city or country == "JP": city_code = "tyo"
            elif "singapore" in city or country == "SG": city_code = "sin"
            elif "london" in city or country == "GB": city_code = "lhr"
            elif "hangzhou" in city or "zhejiang" in city: city_code = "hgh"
            elif "shanghai" in city: city_code = "sha"
            elif "beijing" in city: city_code = "pek"
            elif "guangzhou" in city or "shenzhen" in city: city_code = "can"
            elif "san jose" in city or "san francisco" in city or "los angeles" in city: city_code = "sjc"
            else: city_code = country.lower()

            isp_code = "v6node" if ":" in clean_ip else "node"
            if "hetzner" in isp: isp_code = "hetzner"
            elif "alibaba" in isp or "aliyun" in isp: isp_code = "aliyun"
            elif "tencent" in isp: isp_code = "tencent"
            elif "digitalocean" in isp: isp_code = "do"
            elif "linode" in isp or "akamai" in isp: isp_code = "linode"
            elif "telecom" in isp or "chinatelecom" in isp: isp_code = "ct"
            elif "unicom" in isp or "chinaunicom" in isp: isp_code = "cu"
            elif "mobile" in isp or "chinamobile" in isp: isp_code = "cm"
            elif "aws" in isp or "amazon" in isp: isp_code = "aws"
            elif "google" in isp: isp_code = "gcp"
            elif isp:
                clean_w = ''.join(ch for ch in isp.split()[0] if ch.isalpha()).lower()
                if len(clean_w) >= 2:
                    isp_code = clean_w[:10]

            node_id = f"{city_code}-{isp_code}-vps01"
    except Exception as e:
        logger.warning("Auto node ID generation error: %s", e)

    with _cache_lock:
        _node_id_cache["node_id"] = node_id
        _node_id_cache["timestamp"] = now

    return node_id
