"""
IP Quality Check & Streaming/AI Unlock Detection Module
========================================================
Inspired by bash <(curl -Ls IP.Check.Place) (xykt/IPQuality).

Uses free APIs:
  - ip-api.com   (45 req/min, no key)
  - proxycheck.io (1000 req/day, no key)

Media/AI unlock detection uses direct HTTP probes from this server.
Results are cached for 10 minutes to stay within free-tier limits.
"""

import json
import logging
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
_cache_lock = threading.Lock()
_ip_quality_cache = {}  # {ip: {data: {...}, ts: float}}
CACHE_TTL = 600  # 10 minutes


def _get_cached(ip: str):
    with _cache_lock:
        entry = _ip_quality_cache.get(ip)
        if entry and (time.time() - entry["ts"]) < CACHE_TTL:
            return entry["data"]
    return None


def _set_cached(ip: str, data: dict):
    with _cache_lock:
        _ip_quality_cache[ip] = {"data": data, "ts": time.time()}


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def _http_get(url: str, timeout: int = 5, headers: dict = None) -> urllib.request.Request:
    """Simple GET returning (status_code, response_body, response_headers)."""
    hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, body, dict(e.headers) if hasattr(e, "headers") else {}
    except Exception as e:
        logger.debug("HTTP GET %s failed: %s", url, e)
        return 0, "", {}


def _http_head(url: str, timeout: int = 5) -> tuple:
    """HEAD request returning (status_code, response_headers, redirect_url)."""
    hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}
    req = urllib.request.Request(url, headers=hdrs, method="HEAD")

    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            self.redirect_url = newurl
            return None

    handler = NoRedirectHandler()
    opener = urllib.request.build_opener(handler, urllib.request.HTTPSHandler(context=_SSL_CTX))
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.status, dict(resp.headers), None
    except urllib.error.HTTPError as e:
        redirect_url = getattr(handler, "redirect_url", None)
        return e.code, dict(e.headers) if hasattr(e, "headers") else {}, redirect_url
    except Exception as e:
        logger.debug("HTTP HEAD %s failed: %s", url, e)
        return 0, {}, None


# ---------------------------------------------------------------------------
# 1. IP Basic Info (ip-api.com)
# ---------------------------------------------------------------------------
def _query_ip_api(ip: str) -> dict:
    """Query ip-api.com for basic IP information."""
    fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
    url = f"http://ip-api.com/json/{ip}?fields={fields}&lang=zh-CN"
    status, body, _ = _http_get(url, timeout=4)
    if status == 200 and body:
        try:
            data = json.loads(body)
            if data.get("status") == "success":
                return data
        except json.JSONDecodeError:
            pass
    return {}


# ---------------------------------------------------------------------------
# 2. IP Risk Score (proxycheck.io)
# ---------------------------------------------------------------------------
def _query_proxycheck(ip: str) -> dict:
    """Query proxycheck.io for risk/proxy/VPN detection."""
    url = f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1&port=1&seen=1&days=7&tag=console-web"
    status, body, _ = _http_get(url, timeout=5)
    if status == 200 and body:
        try:
            data = json.loads(body)
            if data.get("status") == "ok" and ip in data:
                return data[ip]
        except json.JSONDecodeError:
            pass
    return {}


# ---------------------------------------------------------------------------
# 3. Media & AI Unlock Detection
# ---------------------------------------------------------------------------

def _check_netflix() -> dict:
    """Check Netflix unlock status."""
    try:
        # Netflix self-made content (Squid Game region test)
        status, body, headers = _http_get(
            "https://www.netflix.com/title/81006049",
            timeout=6,
            headers={"Accept-Language": "en-US,en;q=0.9"}
        )
        if status == 403:
            return {"name": "Netflix", "status": "blocked", "region": None}
        if status == 404:
            return {"name": "Netflix", "status": "blocked", "region": None}
        if status in (200, 301, 302):
            # Try to detect region from page
            region = None
            if "Netflix" in body or status == 200:
                # Try to get region from another endpoint
                s2, b2, _ = _http_get("https://www.netflix.com/api/geo", timeout=4)
                if s2 == 200 and b2:
                    try:
                        geo = json.loads(b2)
                        region = geo.get("country", {}).get("code") or geo.get("countryCode")
                    except Exception:
                        pass
                return {"name": "Netflix", "status": "unlocked", "region": region}
        return {"name": "Netflix", "status": "failed", "region": None}
    except Exception as e:
        logger.debug("Netflix check failed: %s", e)
        return {"name": "Netflix", "status": "failed", "region": None}


def _check_youtube_premium() -> dict:
    """Check YouTube Premium availability."""
    try:
        status, body, _ = _http_get(
            "https://www.youtube.com/premium",
            timeout=6,
            headers={"Accept-Language": "en-US,en;q=0.9"}
        )
        if status == 200:
            region = None
            # Look for region code in page
            if '"GL":"' in body:
                try:
                    region = body.split('"GL":"')[1].split('"')[0]
                except Exception:
                    pass
            elif '"INNERTUBE_CONTEXT_GL":"' in body:
                try:
                    region = body.split('"INNERTUBE_CONTEXT_GL":"')[1].split('"')[0]
                except Exception:
                    pass
            if "Premium" in body or "premium" in body:
                return {"name": "YouTube Premium", "status": "unlocked", "region": region}
            return {"name": "YouTube Premium", "status": "blocked", "region": region}
        return {"name": "YouTube Premium", "status": "failed", "region": None}
    except Exception:
        return {"name": "YouTube Premium", "status": "failed", "region": None}


def _check_disney() -> dict:
    """Check Disney+ unlock status."""
    try:
        status, body, _ = _http_get(
            "https://www.disneyplus.com/",
            timeout=6,
            headers={"Accept-Language": "en-US,en;q=0.9"}
        )
        if status == 200:
            if "not available" in body.lower() or "unavailable" in body.lower():
                return {"name": "Disney+", "status": "blocked", "region": None}
            return {"name": "Disney+", "status": "unlocked", "region": None}
        if status == 403:
            return {"name": "Disney+", "status": "blocked", "region": None}
        return {"name": "Disney+", "status": "failed", "region": None}
    except Exception:
        return {"name": "Disney+", "status": "failed", "region": None}


def _check_tiktok() -> dict:
    """Check TikTok availability."""
    try:
        status, body, _ = _http_get("https://www.tiktok.com/", timeout=6)
        if status == 200:
            if "tiktok" in body.lower():
                return {"name": "TikTok", "status": "unlocked", "region": None}
        if status == 403:
            return {"name": "TikTok", "status": "blocked", "region": None}
        return {"name": "TikTok", "status": "unlocked", "region": None}
    except Exception:
        return {"name": "TikTok", "status": "failed", "region": None}


def _check_chatgpt() -> dict:
    """Check ChatGPT (OpenAI) accessibility."""
    try:
        status, body, _ = _http_get(
            "https://chat.openai.com/",
            timeout=6,
            headers={"Accept-Language": "en-US,en;q=0.9"}
        )
        if status in (200, 302, 301):
            return {"name": "ChatGPT", "status": "unlocked", "region": None}
        if status == 403:
            if "blocked" in body.lower() or "access denied" in body.lower() or "cloudflare" in body.lower():
                return {"name": "ChatGPT", "status": "blocked", "region": None}
        return {"name": "ChatGPT", "status": "unlocked", "region": None}
    except Exception:
        return {"name": "ChatGPT", "status": "failed", "region": None}


def _check_claude() -> dict:
    """Check Claude (Anthropic) accessibility."""
    try:
        status, body, _ = _http_get("https://claude.ai/", timeout=6)
        if status in (200, 302, 301):
            return {"name": "Claude", "status": "unlocked", "region": None}
        if status == 403:
            return {"name": "Claude", "status": "blocked", "region": None}
        return {"name": "Claude", "status": "unlocked", "region": None}
    except Exception:
        return {"name": "Claude", "status": "failed", "region": None}


def _check_spotify() -> dict:
    """Check Spotify availability."""
    try:
        status, body, _ = _http_get("https://open.spotify.com/", timeout=6)
        if status in (200, 302, 301):
            return {"name": "Spotify", "status": "unlocked", "region": None}
        if status == 403:
            return {"name": "Spotify", "status": "blocked", "region": None}
        return {"name": "Spotify", "status": "unlocked", "region": None}
    except Exception:
        return {"name": "Spotify", "status": "failed", "region": None}


def _check_amazon_prime() -> dict:
    """Check Amazon Prime Video availability."""
    try:
        status, body, _ = _http_get("https://www.primevideo.com/", timeout=6)
        if status in (200, 301, 302):
            return {"name": "Amazon Prime", "status": "unlocked", "region": None}
        if status == 403:
            return {"name": "Amazon Prime", "status": "blocked", "region": None}
        return {"name": "Amazon Prime", "status": "failed", "region": None}
    except Exception:
        return {"name": "Amazon Prime", "status": "failed", "region": None}


# All media/AI checks
MEDIA_CHECKS = [
    _check_netflix,
    _check_youtube_premium,
    _check_disney,
    _check_tiktok,
    _check_chatgpt,
    _check_claude,
    _check_spotify,
    _check_amazon_prime,
]


# ---------------------------------------------------------------------------
# Main Aggregator
# ---------------------------------------------------------------------------
def get_ip_quality(ip: str = None, force: bool = False) -> dict:
    """
    Run a full IP quality check.
    Returns a dict with keys: basic, risk, media, timestamp
    """
    if not ip:
        # Detect public IP
        try:
            req = urllib.request.Request("https://ifconfig.me", headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                ip = resp.read().decode().strip()
        except Exception:
            ip = "unknown"

    if not force:
        cached = _get_cached(ip)
        if cached:
            logger.info("IP quality check for %s served from cache", ip)
            return cached

    logger.info("Running IP quality check for %s", ip)

    result = {
        "ip": ip,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "basic": {},
        "risk": {},
        "media": [],
    }

    with ThreadPoolExecutor(max_workers=12) as pool:
        # Submit IP info queries
        future_ipapi = pool.submit(_query_ip_api, ip)
        future_proxycheck = pool.submit(_query_proxycheck, ip)

        # Submit all media/AI checks in parallel
        media_futures = {pool.submit(check_fn): check_fn.__name__ for check_fn in MEDIA_CHECKS}

        # Collect IP info
        try:
            ipapi_data = future_ipapi.result(timeout=8)
        except Exception:
            ipapi_data = {}

        try:
            proxycheck_data = future_proxycheck.result(timeout=8)
        except Exception:
            proxycheck_data = {}

        # Collect media results
        media_results = []
        for future in as_completed(media_futures, timeout=12):
            try:
                media_results.append(future.result())
            except Exception as e:
                name = media_futures[future].replace("_check_", "").title()
                media_results.append({"name": name, "status": "failed", "region": None})

    # Build basic info
    result["basic"] = {
        "ip": ip,
        "asn": ipapi_data.get("as", "N/A"),
        "asname": ipapi_data.get("asname", "N/A"),
        "org": ipapi_data.get("org", "N/A"),
        "isp": ipapi_data.get("isp", "N/A"),
        "country": ipapi_data.get("country", "N/A"),
        "countryCode": ipapi_data.get("countryCode", ""),
        "region": ipapi_data.get("regionName", "N/A"),
        "city": ipapi_data.get("city", "N/A"),
        "lat": ipapi_data.get("lat"),
        "lon": ipapi_data.get("lon"),
        "timezone": ipapi_data.get("timezone", "N/A"),
    }

    # Build risk info - combine ip-api and proxycheck
    is_mobile = ipapi_data.get("mobile", False)
    is_proxy = ipapi_data.get("proxy", False)
    is_hosting = ipapi_data.get("hosting", False)

    # Determine IP type
    if is_mobile:
        ip_type = "mobile"
        ip_type_label = "手机网络"
    elif is_hosting:
        ip_type = "hosting"
        ip_type_label = "数据中心/机房"
    elif is_proxy:
        ip_type = "proxy"
        ip_type_label = "代理"
    else:
        ip_type = "isp"
        ip_type_label = "家宽/ISP"

    # proxycheck enrichment
    pc_type = proxycheck_data.get("type", "").lower()
    if pc_type:
        type_map = {
            "residential": ("isp", "家宽/住宅"),
            "wireless": ("mobile", "手机/无线"),
            "business": ("business", "商业宽带"),
            "hosting": ("hosting", "数据中心/机房"),
            "vpn": ("vpn", "VPN"),
            "tor": ("tor", "Tor 出口"),
        }
        if pc_type in type_map:
            ip_type, ip_type_label = type_map[pc_type]

    # Risk score from proxycheck
    risk_score = proxycheck_data.get("risk", 0)
    try:
        risk_score = int(risk_score)
    except (ValueError, TypeError):
        risk_score = 0

    if risk_score <= 15:
        risk_level = "very_low"
        risk_label = "极低风险"
    elif risk_score <= 33:
        risk_level = "low"
        risk_label = "低风险"
    elif risk_score <= 66:
        risk_level = "medium"
        risk_label = "中等风险"
    elif risk_score <= 85:
        risk_level = "high"
        risk_label = "高风险"
    else:
        risk_level = "very_high"
        risk_label = "极高风险"

    result["risk"] = {
        "ip_type": ip_type,
        "ip_type_label": ip_type_label,
        "is_proxy": is_proxy or proxycheck_data.get("proxy") == "yes",
        "is_vpn": proxycheck_data.get("vpn") == "yes" if proxycheck_data else False,
        "is_tor": proxycheck_data.get("tor") == "yes" if proxycheck_data else False,
        "is_hosting": is_hosting,
        "is_mobile": is_mobile,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "provider": proxycheck_data.get("provider", None),
    }

    # Sort media results in a stable order
    media_order = ["Netflix", "YouTube Premium", "Disney+", "TikTok", "ChatGPT", "Claude", "Spotify", "Amazon Prime"]
    media_map = {m["name"]: m for m in media_results}
    result["media"] = [media_map[name] for name in media_order if name in media_map]
    # Append any extras not in the order list
    for m in media_results:
        if m["name"] not in media_order:
            result["media"].append(m)

    _set_cached(ip, result)
    logger.info("IP quality check for %s completed (risk=%s, type=%s)", ip, risk_score, ip_type)
    return result
