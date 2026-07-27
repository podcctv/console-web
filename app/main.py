import json
import logging
import os
import platform
import shlex
import socket
import subprocess
import time
import threading
import urllib.parse
import urllib.request
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import psutil
from flask import Flask, render_template_string, jsonify, Response, stream_with_context, request

try:
    from app import acme_manager
except ImportError:
    import acme_manager

try:
    from app import ip_quality
except ImportError:
    import ip_quality

def configure_logging():
    log_dir = Path(__file__).resolve().parent.parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "console-web.log"

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    if not any(isinstance(h, RotatingFileHandler) and Path(h.baseFilename) == log_file for h in root_logger.handlers):
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=1_048_576,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        root_logger.addHandler(stream_handler)


configure_logging()
logger = logging.getLogger(__name__)

app = Flask(__name__)
start_time = datetime.now()
host_boot_time = datetime.fromtimestamp(psutil.boot_time())

# Start ACME Auto-renewal daemon thread
try:
    acme_manager.start_daemon()
except Exception as e:
    logger.warning("Failed to start ACME auto-renew daemon: %s", e)

logger.info(
    "console-web starting (pid=%s, platform=%s %s, python=%s)",
    os.getpid(),
    platform.system(),
    platform.release(),
    platform.python_version(),
)

# Track last network counters to compute realtime speed
try:
    _last_net = psutil.net_io_counters()
except Exception:
    _last_net = None
_last_time = datetime.now()

# Cache mechanisms to avoid blocking API calls
_cache_lock = threading.Lock()
_public_ip_cache = {"ip": None, "timestamp": 0}
_isp_cache = {"full": None, "short": None, "timestamp": 0}
CLIENT_ISP_CACHE = {}

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


ISP_FULL_NAME = None
ISP_SHORT_NAME = None


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
            logger.info("ISP info updated: full=%s, short=%s", full, short)


def get_public_ip():
    now = time.time()
    with _cache_lock:
        if _public_ip_cache["ip"] and (now - _public_ip_cache["timestamp"] < 300):
            return _public_ip_cache["ip"]

    try:
        req = urllib.request.Request("https://ifconfig.me", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            pub_ip = resp.read().decode().strip()
            with _cache_lock:
                _public_ip_cache["ip"] = pub_ip
                _public_ip_cache["timestamp"] = now
            return pub_ip
    except Exception:
        with _cache_lock:
            return _public_ip_cache["ip"] or "N/A"


PING_TARGETS = {
    "ping_cu": "zj-cu-v4.ip.zstaticcdn.com:80",
    "ping_cm": "zj-cm-v4.ip.zstaticcdn.com:80",
    "ping_ct": "zj-ct-v4.ip.zstaticcdn.com:80",
}

COMMANDS = {
    "ping": lambda target, extra: ["ping", *extra, target]
    if extra
    else ["ping", "-c", "4", target],
    "mtr": lambda target, extra: ["mtr", *extra, target]
    if extra
    else ["mtr", "-w", "-c", "5", target],
}


@app.route("/.well-known/acme-challenge/<token>")
def acme_challenge_route(token):
    token_file = acme_manager.CHALLENGE_DIR / token
    if token_file.exists():
        return Response(token_file.read_text(), mimetype="text/plain")
    return Response("token not found", status=404)


@app.route("/acme/status")
def acme_status_route():
    return jsonify(acme_manager.get_cert_status())


@app.route("/acme/issue")
def acme_issue_route():
    target = request.args.get("target", "").strip() or None
    email = request.args.get("email", "").strip() or None
    success, msg = acme_manager.issue_cert(target, email)
    return jsonify(success=success, message=msg)


@app.route("/acme/renew")
def acme_renew_route():
    success, msg = acme_manager.renew_cert()
    return jsonify(success=success, message=msg)


@app.route("/ipcheck")
def ipcheck_route():
    """Run IP quality check and return JSON results."""
    force = request.args.get("force", "").lower() in ("1", "true", "yes")
    try:
        result = ip_quality.get_ip_quality(force=force)
        return jsonify(result)
    except Exception as e:
        logger.exception("IP quality check failed")
        return jsonify(error=str(e)), 500


@app.route("/run/<cmd>")
def run_cmd(cmd):
    target = request.args.get("target", "")
    raw_args = request.args.get("args", "")
    if cmd not in COMMANDS:
        logger.warning("Unsupported command received: %s", cmd)
        return Response("unsupported command", status=400)
    if not target:
        logger.warning("Command %s missing target", cmd)
        return Response("target required", status=400)
    extra_args = shlex.split(raw_args) if raw_args else []
    try:
        args = COMMANDS[cmd](target, extra_args)
        logger.info(
            "Executing command: cmd=%s target=%s args=%s remote=%s",
            cmd,
            target,
            extra_args,
            request.headers.get("X-Forwarded-For", request.remote_addr),
        )
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    except Exception as e:
        err = e
        logger.exception("Failed to start command %s %s", cmd, target)
        def generate_error():
            yield f"data: unable to execute: {err}\n\n"
            yield "data: [exit 1]\n\n"
        return Response(stream_with_context(generate_error()), mimetype="text/event-stream")

    def generate():
        for line in iter(proc.stdout.readline, ""):
            yield f"data: {line.rstrip()}\n\n"
        proc.wait()
        yield f"data: [exit {proc.returncode}]\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


def query_isp(ip: str):
    if not ip or ip == "127.0.0.1" or ip.startswith("192.168.") or ip.startswith("10."):
        return "局域网/本地"
    try:
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=isp", headers={"User-Agent": "console-web/1.6"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            return json.loads(resp.read().decode()).get("isp")
    except Exception:
        return None


@app.route("/pinginfo")
def ping_info():
    url = request.args.get("url", "").strip()
    if not url:
        logger.warning("/pinginfo missing url parameter")
        return Response("url required", status=400)
    parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname
    if not host:
        logger.warning("/pinginfo invalid url: %s", url)
        return Response("invalid url", status=400)
    port = parsed.port or 80
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        logger.exception("Failed to resolve host %s", host)
        ip = None
    latency = tcp_ping(f"{host}:{port}")
    isp = query_isp(ip) if ip else None
    return jsonify(ip=ip, isp=isp, ping=latency, host=host)


def tcp_ping(host: str):
    try:
        if ":" in host:
            host, port = host.rsplit(":", 1)
            port = int(port)
        else:
            port = 80
        start = datetime.now()
        with socket.create_connection((host, port), timeout=1):
            end = datetime.now()
        return (end - start).total_seconds() * 1000
    except Exception:
        return None


def icmp_ping(ip: str):
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
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


@app.route("/pings")
def pings():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    with ThreadPoolExecutor(max_workers=len(PING_TARGETS) + 1) as executor:
        futures = {
            executor.submit(tcp_ping, host): key
            for key, host in PING_TARGETS.items()
        }
        if client_ip and client_ip != "127.0.0.1":
            futures[executor.submit(icmp_ping, client_ip)] = "client_ping"
        results = {key: future.result() for future, key in futures.items()}

    if "client_ping" not in results:
        results["client_ping"] = None
    return jsonify(results)


def humanize(seconds: int) -> str:
    seconds = int(seconds)
    years, seconds = divmod(seconds, 31536000)
    months, seconds = divmod(seconds, 2592000)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = []
    if years:
        parts.append(f"{years}年")
    if months:
        parts.append(f"{months}月")
    if days:
        parts.append(f"{days}天")
    if hours:
        parts.append(f"{hours}小时")
    if minutes:
        parts.append(f"{minutes}分")
    if seconds or not parts:
        parts.append(f"{seconds}秒")
    return " ".join(parts)


def humanize_bytes(size: float) -> str:
    if size is None:
        return "N/A"
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}EB"


TEMPLATE = r"""
<!DOCTYPE html>
<html lang="zh-CN" data-theme="neon">
<head>
    <meta charset="UTF-8">
    <title>{{ hostname }} - Cyber Operations Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            /* Sci-Fi Blue Surface & Background Palette */
            --bg-page: #040912;
            --bg-surface: #081220;
            --bg-surface-elevated: #0d1b30;
            --bg-hover: #112440;
            --bg-input: #060e1b;

            /* Subdued Muted Borders */
            --border-subtle: rgba(0, 217, 255, 0.08);
            --border-default: rgba(0, 217, 255, 0.14);
            --border-active: rgba(0, 217, 255, 0.45);

            /* Typography & Colors */
            --text-primary: #e8f1f7;
            --text-secondary: #9cb0bd;
            --text-muted: #607785;

            /* Semantic Color Tokens */
            --accent: #00d9ff;
            --accent-soft: rgba(0, 217, 255, 0.10);
            --info: #00d9ff;
            --info-soft: rgba(0, 217, 255, 0.10);
            --warning: #f5b942;
            --warning-soft: rgba(245, 185, 66, 0.10);
            --orange: #f58442;
            --orange-soft: rgba(245, 132, 66, 0.10);
            --danger: #f35b72;
            --danger-soft: rgba(243, 91, 114, 0.10);
            --success: #36e27b;
            --success-soft: rgba(54, 226, 123, 0.10);

            /* Layout Tokens */
            --radius-card: 10px;
            --radius-control: 6px;

            /* Typography */
            --font-ui: "MiSans", "HarmonyOS Sans SC", "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: "JetBrains Mono", "IBM Plex Mono", "Consolas", monospace;
        }

        [data-theme="matrix"] {
            --bg-page: #050807;
            --bg-surface: #08110d;
            --bg-surface-elevated: #0d1a14;
            --bg-hover: #10221a;
            --bg-input: #09150e;

            --border-subtle: rgba(93, 255, 167, 0.08);
            --border-default: rgba(93, 255, 167, 0.14);
            --border-active: rgba(71, 255, 148, 0.45);

            --text-primary: #e8f3ed;
            --text-secondary: #8da496;
            --text-muted: #52665a;

            --accent: #36e27b;
            --accent-soft: rgba(54, 226, 123, 0.10);
        }

        [data-theme="cyberpunk"] {
            --bg-page: #07040e;
            --bg-surface: #12091c;
            --bg-surface-elevated: #1a0d28;
            --bg-hover: #221235;
            --bg-input: #0f071a;

            --border-subtle: rgba(255, 0, 119, 0.08);
            --border-default: rgba(255, 0, 119, 0.14);
            --border-active: rgba(255, 0, 119, 0.45);

            --text-primary: #ffe5f7;
            --text-secondary: #9c84b8;
            --text-muted: #614c7a;

            --accent: #ff0077;
            --accent-soft: rgba(255, 0, 119, 0.10);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body { min-height: 100%; background: var(--bg-page); color: var(--text-primary); font-family: var(--font-ui); -webkit-font-smoothing: antialiased; }

        body {
            display: flex; flex-direction: column; align-items: center; padding: 24px 0;
            background-image: 
                radial-gradient(circle at 50% 0%, rgba(0, 217, 255, 0.04), transparent 70%),
                linear-gradient(to bottom, rgba(255,255,255,0.008) 1px, transparent 1px);
            background-size: 100% 100%, 100% 24px;
        }

        /* Rule 1: Unified Page Container across ALL modules */
        .page-container {
            width: min(1440px, calc(100% - 48px));
            margin-inline: auto;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .mono { font-family: var(--font-mono); font-variant-numeric: tabular-nums; }
        .text-success { color: var(--success); }
        .text-warning { color: var(--warning); }
        .text-orange { color: var(--orange); }
        .text-danger { color: var(--danger); }
        .text-info { color: var(--info); }
        .text-muted { color: var(--text-muted); }

        /* Top Navigation Header (12 Columns) */
        .header-bar {
            width: 100%;
            display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;
            background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: var(--radius-card);
            padding: 12px 20px; backdrop-filter: blur(16px);
        }

        .brand-group {
            display: flex; align-items: center; gap: 12px; font-size: 1.1rem; font-weight: 700; color: var(--text-primary);
        }

        .brand-icon {
            display: inline-flex; align-items: center; justify-content: center;
            width: 32px; height: 32px; border-radius: var(--radius-control); background: var(--accent-soft);
            border: 1px solid var(--border-default); color: var(--accent); font-family: var(--font-mono); font-weight: 700;
        }

        .status-light-group { display: flex; align-items: center; gap: 16px; }

        .status-dot-item {
            display: inline-flex; align-items: center; gap: 6px; font-size: 0.78rem; font-weight: 500; color: var(--text-secondary);
        }

        .pulse-dot {
            width: 7px; height: 7px; border-radius: 50%; background: var(--success);
            box-shadow: 0 0 6px var(--success); animation: pulse 2s infinite;
        }

        .pulse-dot.dot-warning { background: var(--warning); box-shadow: 0 0 6px var(--warning); }
        .pulse-dot.dot-orange { background: var(--orange); box-shadow: 0 0 6px var(--orange); }

        @keyframes pulse {
            0% { opacity: 0.7; transform: scale(0.95); }
            50% { opacity: 1; transform: scale(1.25); }
            100% { opacity: 0.7; transform: scale(0.95); }
        }

        .controls-group { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

        .btn-ctrl, .select-input {
            background: var(--bg-input); border: 1px solid var(--border-default); color: var(--text-primary);
            padding: 5px 12px; border-radius: var(--radius-control); font-family: var(--font-ui); font-size: 0.78rem;
            cursor: pointer; transition: all 0.2s ease; outline: none; display: inline-flex; align-items: center; gap: 6px;
        }

        .btn-ctrl:hover, .select-input:hover {
            border-color: var(--border-active); background: var(--bg-hover);
        }

        /* Rule 2 & 3: Restored 4 Uniform Summary Cards in 1 Row (104-124px Height) */
        .summary-grid {
            width: 100%;
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 16px;
        }

        .summary-card {
            height: 114px;
            background: var(--bg-surface);
            border: 1px solid var(--border-default);
            border-radius: var(--radius-card);
            padding: 14px 18px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: background 0.2s ease, border-color 0.2s ease;
        }

        .summary-card:hover {
            background: var(--bg-surface-elevated); border-color: var(--border-active);
        }

        .summary-card.hero-card {
            background: linear-gradient(135deg, var(--bg-surface), var(--bg-surface-elevated));
            border-color: rgba(0, 217, 255, 0.28);
        }

        .summary-label {
            font-size: 0.76rem; font-weight: 500; color: var(--text-secondary); display: flex; justify-content: space-between; align-items: center;
        }

        .summary-value {
            font-size: 2rem; font-weight: 700; color: var(--text-primary); line-height: 1.1;
            display: flex; align-items: baseline; gap: 6px;
        }

        .summary-unit { font-size: 0.9rem; font-weight: 500; color: var(--text-muted); }

        .summary-desc {
            font-size: 0.74rem; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }

        .btn-copy {
            background: transparent; border: 1px solid var(--border-subtle); color: var(--text-secondary); cursor: pointer;
            padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; transition: all 0.15s ease;
        }

        .btn-copy:hover { color: var(--accent); border-color: var(--border-default); background: var(--accent-soft); }

        /* Rule 2 & 5: 12-Column Responsive Dashboard Grid */
        .dashboard-grid {
            width: 100%;
            display: grid;
            grid-template-columns: repeat(12, minmax(0, 1fr));
            gap: 16px;
        }

        .col-12 { grid-column: span 12; }
        .col-7  { grid-column: span 7; }
        .col-5  { grid-column: span 5; }

        .card {
            width: 100%;
            background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: var(--radius-card);
            padding: 18px 20px; display: flex; flex-direction: column; gap: 16px; transition: border-color 0.2s ease;
        }

        .card:hover { border-color: var(--border-active); }

        .card-header {
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid var(--border-subtle); padding-bottom: 10px; font-weight: 600;
            font-size: 0.92rem; color: var(--text-primary);
        }

        .card-header-left { display: flex; align-items: center; gap: 8px; }

        /* Rule 6: System Metrics Gauges */
        .metrics-triple {
            display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;
        }

        .metric-box {
            background: var(--bg-input); border: 1px solid var(--border-subtle); border-radius: var(--radius-control);
            padding: 10px 12px; display: flex; flex-direction: column; gap: 6px;
        }

        .metric-header {
            display: flex; justify-content: space-between; align-items: center; font-size: 0.76rem;
        }

        .metric-name { color: var(--text-secondary); font-weight: 500; }
        .metric-badge { font-size: 0.68rem; font-weight: 600; padding: 1px 6px; border-radius: 4px; }
        .badge-normal { background: var(--success-soft); color: var(--success); }
        .badge-warn { background: var(--warning-soft); color: var(--warning); }
        .badge-danger { background: var(--danger-soft); color: var(--danger); }

        .metric-val-num { font-size: 1.15rem; font-weight: 700; color: var(--text-primary); }

        .progress-track {
            height: 6px; background: rgba(255,255,255,0.05); border-radius: 3px; overflow: hidden; position: relative; margin-top: 2px;
        }

        .progress-fill {
            height: 100%; width: 0%; background: var(--info); border-radius: 3px;
            transition: width 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .progress-fill.warn { background: var(--warning); }
        .progress-fill.danger { background: var(--danger); }

        /* System Info Matrix with Split LAN / Public IP Lines */
        .info-subgroups { display: flex; flex-direction: column; gap: 12px; }

        .info-subgroup-title {
            font-size: 0.74rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase;
            letter-spacing: 0.5px; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;
        }

        .info-list-matrix {
            display: grid; grid-template-columns: repeat(2, 1fr); gap: 4px 16px; font-size: 0.78rem;
        }

        .info-row {
            display: flex; justify-content: space-between; align-items: center;
            padding: 5px 8px; border-radius: 4px; transition: background 0.15s ease;
        }

        .info-row:hover { background: var(--bg-hover); }
        .info-key { color: var(--text-secondary); font-size: 0.76rem; }
        .info-val { color: var(--text-primary); font-weight: 600; text-align: right; word-break: break-all; }

        /* Rule 7: Refined Sci-Fi Blue TCP Ping Sparkline Monitor */
        .ping-grid { display: flex; flex-direction: column; gap: 10px; }

        .ping-item {
            height: 100px;
            background: var(--bg-input); border: 1px solid var(--border-subtle); border-radius: var(--radius-control);
            padding: 10px 14px; display: flex; flex-direction: column; justify-content: space-between;
        }

        .ping-item-header {
            display: flex; justify-content: space-between; align-items: center; font-size: 0.82rem;
        }

        .ping-title { font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 6px; }
        .ping-meta { font-size: 0.72rem; color: var(--text-muted); display: flex; gap: 12px; }
        .ping-value { font-weight: 700; font-size: 0.95rem; }

        .pixel-bar-container {
            display: flex; align-items: flex-end; gap: 2px; height: 32px;
            padding: 2px 4px; background: rgba(0,0,0,0.3); border-radius: 4px;
            border: 1px solid var(--border-subtle); overflow: hidden; position: relative;
        }

        .pixel-bar-container::before {
            content: ''; position: absolute; left: 4px; right: 4px; bottom: 16px;
            border-top: 1px dashed rgba(255,255,255,0.06);
        }

        .pixel-bar {
            flex: 1; min-width: 4px; max-width: 8px; border-radius: 1px 1px 0 0;
            transition: height 0.2s ease, background 0.2s ease;
        }

        .pixel-bar.px-cyan { background: var(--info); }
        .pixel-bar.px-yellow { background: var(--warning); }
        .pixel-bar.px-orange { background: var(--orange); }
        .pixel-bar.px-red { background: var(--danger); }
        .pixel-bar.px-timeout { background: var(--danger); min-height: 2px; }
        .pixel-bar.px-empty { background: rgba(255,255,255,0.02); min-height: 2px; }

        /* Rule 8: IP Quality Full-Width Panel with 4:3:5 Internal Grid */
        .ipcheck-card {
            width: 100%; grid-column: span 12;
            background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: var(--radius-card);
            padding: 18px 20px; display: flex; flex-direction: column; gap: 14px; transition: border-color 0.2s ease;
        }

        .ipcheck-card:hover { border-color: var(--border-active); }

        .ipcheck-info-row {
            display: grid; grid-template-columns: 4fr 3fr 5fr; gap: 16px;
        }

        .ipcheck-section {
            background: var(--bg-input); border: 1px solid var(--border-subtle); border-radius: var(--radius-control);
            padding: 12px 14px; display: flex; flex-direction: column; gap: 6px;
        }

        .ipcheck-section-title {
            font-size: 0.78rem; font-weight: 600; color: var(--text-secondary);
            border-bottom: 1px solid var(--border-subtle); padding-bottom: 6px; margin-bottom: 2px;
            display: flex; align-items: center; gap: 6px;
        }

        .ipcheck-row {
            display: flex; justify-content: space-between; align-items: center;
            font-size: 0.76rem; padding: 3px 0;
        }

        .ipcheck-label { color: var(--text-secondary); min-width: 88px; }
        .ipcheck-val { color: var(--text-primary); font-weight: 600; text-align: right; word-break: break-word; }

        .risk-score-display {
            display: flex; justify-content: space-between; align-items: baseline; margin-top: 2px;
        }
        .risk-score-num { font-size: 1.5rem; font-weight: 700; font-family: var(--font-mono); }

        .risk-bar-segmented {
            display: flex; gap: 3px; height: 7px; border-radius: 4px; overflow: hidden; margin-top: 4px;
        }

        .risk-segment { flex: 1; height: 100%; background: rgba(255,255,255,0.06); transition: background 0.3s ease; }
        .risk-segment.active-green { background: var(--success); }
        .risk-segment.active-yellow { background: var(--warning); }
        .risk-segment.active-orange { background: var(--orange); }
        .risk-segment.active-red { background: var(--danger); }

        .risk-factors-container {
            display: flex; flex-direction: column; gap: 4px; margin-top: 6px; background: rgba(0,0,0,0.2);
            padding: 8px 10px; border-radius: 4px; border: 1px solid var(--border-subtle);
        }

        .risk-factor-row {
            display: flex; justify-content: space-between; align-items: center; font-size: 0.72rem; color: var(--text-secondary);
        }

        .risk-advice-box {
            font-size: 0.74rem; color: var(--text-secondary); line-height: 1.45; margin-top: 6px;
            padding: 8px 10px; background: rgba(0, 217, 255, 0.04); border-radius: 4px; border: 1px solid var(--border-subtle);
        }

        /* Tag Badges */
        .badge-tag {
            display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px;
            font-size: 0.72rem; font-weight: 600; font-family: var(--font-ui);
        }
        .badge-tag-yes { background: var(--warning-soft); color: var(--warning); border: 1px solid rgba(245, 185, 66, 0.25); }
        .badge-tag-no { background: var(--success-soft); color: var(--success); border: 1px solid rgba(54, 226, 123, 0.25); }
        .badge-tag-high { background: var(--danger-soft); color: var(--danger); border: 1px solid rgba(243, 91, 114, 0.25); }

        /* Rule 9: Streaming & AI Full-Width Grid (4 Columns, 2-Row Tiles) */
        .streaming-card {
            width: 100%; grid-column: span 12;
            background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: var(--radius-card);
            padding: 18px 20px; display: flex; flex-direction: column; gap: 14px; transition: border-color 0.2s ease;
        }

        .unlock-header-right { display: flex; align-items: center; gap: 10px; }

        .filter-tabs-segmented {
            display: flex; gap: 2px; background: var(--bg-input); padding: 3px;
            border-radius: var(--radius-control); border: 1px solid var(--border-subtle);
        }

        .tab-btn-seg {
            background: transparent; border: none; color: var(--text-secondary); padding: 3px 12px;
            border-radius: 4px; font-size: 0.74rem; font-weight: 500; cursor: pointer; transition: all 0.15s ease;
        }

        .tab-btn-seg:hover { color: var(--text-primary); }
        .tab-btn-seg.active { background: var(--accent); color: #000; font-weight: 700; box-shadow: 0 1px 4px rgba(0,0,0,0.4); }

        .unlock-grid {
            width: 100%; display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px;
        }

        .unlock-tile-capsule {
            background: var(--bg-input); border: 1px solid var(--border-subtle); border-radius: var(--radius-control);
            padding: 10px 12px; display: flex; flex-direction: column; gap: 6px;
            transition: border-color 0.2s ease, background 0.2s ease; font-size: 0.78rem;
        }

        .unlock-tile-capsule:hover { border-color: var(--border-default); background: var(--bg-hover); }
        .unlock-tile-top { display: flex; align-items: center; justify-content: space-between; font-weight: 600; color: var(--text-primary); }
        .unlock-tile-bottom { display: flex; align-items: center; justify-content: space-between; font-size: 0.72rem; }

        .unlock-badge {
            display: inline-flex; align-items: center; gap: 3px; padding: 2px 8px; border-radius: 4px;
            font-size: 0.7rem; font-weight: 600; white-space: nowrap;
        }

        .unlock-badge.unlocked { background: var(--success-soft); color: var(--success); border: 1px solid rgba(54, 226, 123, 0.25); }
        .unlock-badge.blocked { background: var(--danger-soft); color: var(--danger); border: 1px solid rgba(243, 91, 114, 0.25); }
        .unlock-badge.unknown { background: var(--warning-soft); color: var(--warning); border: 1px solid rgba(245, 185, 66, 0.25); }

        /* Rule 10: Diagnostic Console Full-Width Alignment */
        .terminal-card {
            width: 100%; grid-column: span 12;
            background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: var(--radius-card);
            padding: 0; overflow: hidden; display: flex; flex-direction: column;
            height: 280px; min-height: 220px; max-height: 600px; transition: height 0.2s ease;
        }

        .terminal-card.expanded { height: 480px; }

        .terminal-toolbar-two-tier {
            display: flex; flex-direction: column; background: var(--bg-surface-elevated);
            border-bottom: 1px solid var(--border-subtle);
        }

        .toolbar-top-tier {
            padding: 8px 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;
        }

        .toolbar-bottom-tier {
            padding: 6px 14px; border-top: 1px dashed var(--border-subtle); display: flex; gap: 6px; flex-wrap: wrap; align-items: center; background: rgba(0,0,0,0.15);
        }

        .terminal-header-left { display: flex; align-items: center; gap: 12px; }
        .terminal-dots { display: flex; gap: 6px; }
        .win-dot { width: 10px; height: 10px; border-radius: 50%; }
        .win-red { background: #ff5f56; }
        .win-yellow { background: #ffbd2e; }
        .win-green { background: #27c93f; }

        .terminal-lookup-bar { display: flex; align-items: center; gap: 6px; flex: 1; min-width: 240px; max-width: 420px; }

        .lookup-input-inline {
            flex: 1; min-width: 0; background: var(--bg-input); border: 1px solid var(--border-subtle); color: var(--text-primary);
            padding: 4px 10px; border-radius: var(--radius-control); font-family: var(--font-mono); font-size: 0.78rem; outline: none;
        }

        .lookup-input-inline:focus { border-color: var(--border-active); }

        .lookup-btn-inline {
            background: var(--accent); color: #000; border: none; padding: 4px 12px;
            border-radius: var(--radius-control); font-weight: 700; font-family: var(--font-ui); font-size: 0.75rem; cursor: pointer;
            transition: opacity 0.2s ease;
        }
        .lookup-btn-inline:hover { opacity: 0.88; }

        .chip-btn {
            background: transparent; border: 1px solid var(--border-subtle); color: var(--text-secondary);
            padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-family: var(--font-ui); cursor: pointer; transition: all 0.15s ease;
        }

        .chip-btn:hover { color: var(--text-primary); border-color: var(--border-default); background: var(--bg-hover); }

        .terminal-body {
            flex: 1; padding: 12px 14px; overflow-y: auto; font-family: var(--font-mono); font-size: 0.82rem; line-height: 1.5;
            display: flex; flex-direction: column; gap: 6px; word-break: break-word; background: var(--bg-page);
        }

        #cmd_output { white-space: pre-wrap; color: var(--text-primary); }

        .terminal-input-line { display: flex; align-items: center; gap: 8px; margin-top: 4px; min-width: 0; }
        .prompt-text { color: var(--info); font-weight: 600; white-space: nowrap; }

        .terminal-input {
            flex: 1; min-width: 0; background: transparent; border: none; outline: none; color: var(--text-primary);
            font-family: var(--font-mono); font-size: 0.82rem; caret-color: var(--accent);
        }

        /* Scrollbars */
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: var(--bg-page); }
        ::-webkit-scrollbar-thumb { background: var(--border-default); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-secondary); }

        /* Responsive Breakpoints */
        @media (min-width: 1024px) and (max-width: 1279px) {
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .col-7, .col-5 { grid-column: span 6; }
            .ipcheck-info-row { grid-template-columns: 1fr; }
        }

        @media (max-width: 1023px) {
            .page-container { width: calc(100% - 24px); }
            .summary-grid { grid-template-columns: 1fr; }
            .dashboard-grid { grid-template-columns: 1fr; }
            .col-7, .col-5 { grid-column: span 12; }
            .metrics-triple { grid-template-columns: 1fr; }
            .info-list-matrix { grid-template-columns: 1fr; }
            .ipcheck-info-row { grid-template-columns: 1fr; }
            .unlock-grid { grid-template-columns: repeat(2, 1fr); }
        }

        @media (max-width: 640px) {
            .unlock-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <!-- Rule 1: Unified Page Container -->
    <div class="page-container">
        <!-- Top Navigation Header -->
        <header class="header-bar">
            <div class="brand-group">
                <span class="brand-icon">&gt;_</span>
                <span>NODE SEEKER</span>
                <span class="text-muted" style="font-size:0.76rem; font-weight:normal">| {{ hostname }}</span>
            </div>

            <!-- Group 2: Lightweight Status Dots -->
            <div class="status-light-group">
                <span class="status-dot-item"><span class="pulse-dot"></span> 系统在线</span>
                <span class="status-dot-item" id="acme_badge"><span class="pulse-dot dot-warning"></span> HTTP 运行中</span>
                <span class="status-dot-item"><span class="pulse-dot dot-orange"></span> 实时同步</span>
            </div>

            <!-- Group 3: Right Controls -->
            <div class="controls-group">
                <select id="theme_select" class="select-input">
                    <option value="neon">🔵 Sci-Fi Blue</option>
                    <option value="matrix">🟢 Matrix Cyber</option>
                    <option value="cyberpunk">🟣 Cyberpunk Neon</option>
                </select>
                <select id="interval_select" class="select-input">
                    <option value="1000">⚡ 1s 刷新</option>
                    <option value="2000">⏱️ 2s 刷新</option>
                    <option value="5000">🐢 5s 刷新</option>
                    <option value="0">⏸️ 暂停</option>
                </select>
                <button class="btn-ctrl" onclick="fetchStats(); fetchPings();">🔄 刷新</button>
                <button class="btn-ctrl" onclick="toggleFullScreen()">⛶ 全屏</button>
            </div>
        </header>

        <!-- Rule 2 & 3: Restored 4 Uniform Summary Cards (104-124px Height) -->
        <div class="summary-grid">
            <!-- Hero Summary Card 1 -->
            <div class="summary-card hero-card">
                <div class="summary-label">
                    <span>综合网络状态</span>
                    <span id="sum_net_dot" class="pulse-dot"></span>
                </div>
                <div class="summary-value" id="sum_net_status">健康</div>
                <div class="summary-desc" id="sum_net_desc">平均 TCP 延迟检测中...</div>
            </div>

            <!-- Summary Card 2: Public Egress IP -->
            <div class="summary-card">
                <div class="summary-label">
                    <span>公网出口 IP</span>
                    <button class="btn-copy" onclick="copyIP()" title="复制出口 IP">📋 复制</button>
                </div>
                <div class="summary-value mono" id="sum_ip_val" style="font-size:1.4rem">37.114.48.47</div>
                <div class="summary-desc" id="sum_ip_desc">德国 · ROETH &amp; BECK GbR</div>
            </div>

            <!-- Summary Card 3: Avg TCP Latency -->
            <div class="summary-card">
                <div class="summary-label">
                    <span>平均 TCP 延迟</span>
                    <span style="font-size:0.72rem" class="text-muted">40s 均值</span>
                </div>
                <div class="summary-value mono" id="sum_ping_val">- <span class="summary-unit">ms</span></div>
                <div class="summary-desc" id="sum_ping_desc">边缘节点延迟计算中...</div>
            </div>

            <!-- Summary Card 4: IP Risk Score -->
            <div class="summary-card">
                <div class="summary-label">
                    <span>IP 风险评分</span>
                    <span style="font-size:0.72rem" class="text-muted">Scamalytics</span>
                </div>
                <div class="summary-value mono" id="sum_risk_val">- <span class="summary-unit">/ 100</span></div>
                <div class="summary-desc" id="sum_risk_desc">欺诈风险体检中...</div>
            </div>
        </div>

        <!-- Rule 2 & 5: 12-Column Dashboard Grid -->
        <div class="dashboard-grid">
            <!-- Left Column: System Telemetry Panel (7 Columns) -->
            <div class="card col-7">
                <div class="card-header">
                    <div class="card-header-left">
                        <span>🖥️</span>
                        <span>系统资源与节点网络</span>
                    </div>
                    <span id="load_val" class="mono text-muted" style="font-size:0.76rem">Load: -</span>
                </div>

                <!-- Triple Indicator Gauges -->
                <div class="metrics-triple">
                    <div class="metric-box">
                        <div class="metric-header">
                            <span class="metric-name">CPU</span>
                            <span class="metric-badge badge-normal" id="cpu_badge">正常</span>
                        </div>
                        <div class="metric-val-num mono" id="cpu_val">0.0%</div>
                        <div class="progress-track">
                            <div class="progress-fill" id="cpu_bar"></div>
                        </div>
                    </div>

                    <div class="metric-box">
                        <div class="metric-header">
                            <span class="metric-name">内存</span>
                            <span class="metric-badge badge-normal" id="memory_badge">正常</span>
                        </div>
                        <div class="metric-val-num mono" id="memory_val">0.0%</div>
                        <div class="progress-track">
                            <div class="progress-fill" id="memory_bar"></div>
                        </div>
                    </div>

                    <div class="metric-box">
                        <div class="metric-header">
                            <span class="metric-name">磁盘</span>
                            <span class="metric-badge badge-normal" id="disk_badge">正常</span>
                        </div>
                        <div class="metric-val-num mono" id="disk_val">0.0%</div>
                        <div class="progress-track">
                            <div class="progress-fill" id="disk_bar"></div>
                        </div>
                    </div>
                </div>

                <!-- System Info Sub-Groups with Split LAN & Public IPs -->
                <div class="info-subgroups">
                    <div>
                        <div class="info-subgroup-title">⚡ 运行状态</div>
                        <div class="info-list-matrix">
                            <div class="info-row">
                                <span class="info-key">网络速率 (上/下)</span>
                                <span class="info-val mono text-success" id="net_io">-</span>
                            </div>
                            <div class="info-row">
                                <span class="info-key">服务器公网 IP</span>
                                <span class="info-val mono text-info" id="public_ip_val">37.114.48.47</span>
                            </div>
                            <div class="info-row">
                                <span class="info-key">服务器内网 IP</span>
                                <span class="info-val mono" id="lan_ip_val">172.17.0.2</span>
                            </div>
                            <div class="info-row">
                                <span class="info-key">客户端 IP &amp; 运营商</span>
                                <span class="info-val mono" id="client_ip_val">-</span>
                            </div>
                            <div class="info-row">
                                <span class="info-key">ACME SSL 证书</span>
                                <span class="info-val mono text-info" id="acme_val">-</span>
                            </div>
                            <div class="info-row">
                                <span class="info-key">容器运行时间</span>
                                <span class="info-val mono" id="cuptime">-</span>
                            </div>
                        </div>
                    </div>

                    <div>
                        <div class="info-subgroup-title">⚙️ 系统参数</div>
                        <div class="info-list-matrix">
                            <div class="info-row">
                                <span class="info-key">宿主机运行时间</span>
                                <span class="info-val mono" id="huptime">-</span>
                            </div>
                            <div class="info-row">
                                <span class="info-key">CPU 核心</span>
                                <span class="info-val mono" id="cpu_cores">-</span>
                            </div>
                            <div class="info-row">
                                <span class="info-key">系统架构</span>
                                <span class="info-val mono" id="arch_val">-</span>
                            </div>
                            <div class="info-row">
                                <span class="info-key">磁盘读写 IO</span>
                                <span class="info-val mono" id="disk_io">-</span>
                            </div>
                            <div class="info-row">
                                <span class="info-key">物理/总内存</span>
                                <span class="info-val mono" id="mem_total_val">-</span>
                            </div>
                            <div class="info-row">
                                <span class="info-key">操作系统内核</span>
                                <span class="info-val mono" id="os_val" title="">-</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Right Column: Edge TCP Ping Latency Monitor Panel (5 Columns) -->
            <div class="card col-5">
                <div class="card-header">
                    <div class="card-header-left">
                        <span>📡</span>
                        <span>边缘网络延迟 (TCP Ping)</span>
                    </div>
                    <div style="font-size:0.72rem; display:flex; gap:8px" class="mono text-muted">
                        <span class="text-info">● &lt;80ms</span>
                        <span class="text-warning">● &lt;160ms</span>
                        <span class="text-orange">● &lt;250ms</span>
                        <span class="text-danger">● &ge;250ms</span>
                    </div>
                </div>

                <div class="ping-grid">
                    <div class="ping-item" id="client_ping_item">
                        <div class="ping-item-header">
                            <span class="ping-title">📍 本地 Client 延迟</span>
                            <div class="ping-value mono text-info" id="client_ping_val">-</div>
                        </div>
                        <div class="ping-meta mono">
                            <span id="client_ping_stat">均值: - | 抖动: -</span>
                            <span id="client_ping_trend" class="text-muted">~ 稳定</span>
                        </div>
                        <div class="pixel-bar-container" id="client_ping_bars"></div>
                    </div>

                    <div class="ping-item">
                        <div class="ping-item-header">
                            <span class="ping-title">🟢 浙江联通 Ping</span>
                            <div class="ping-value mono" id="ping_cu_val">-</div>
                        </div>
                        <div class="ping-meta mono">
                            <span id="ping_cu_stat">均值: - | 抖动: -</span>
                            <span id="ping_cu_trend" class="text-muted">~ 稳定</span>
                        </div>
                        <div class="pixel-bar-container" id="ping_cu_bars"></div>
                    </div>

                    <div class="ping-item">
                        <div class="ping-item-header">
                            <span class="ping-title">🔵 浙江移动 Ping</span>
                            <div class="ping-value mono" id="ping_cm_val">-</div>
                        </div>
                        <div class="ping-meta mono">
                            <span id="ping_cm_stat">均值: - | 抖动: -</span>
                            <span id="ping_cm_trend" class="text-muted">~ 稳定</span>
                        </div>
                        <div class="pixel-bar-container" id="ping_cm_bars"></div>
                    </div>

                    <div class="ping-item">
                        <div class="ping-item-header">
                            <span class="ping-title">🟡 浙江电信 Ping</span>
                            <div class="ping-value mono" id="ping_ct_val">-</div>
                        </div>
                        <div class="ping-meta mono">
                            <span id="ping_ct_stat">均值: - | 抖动: -</span>
                            <span id="ping_ct_trend" class="text-muted">~ 稳定</span>
                        </div>
                        <div class="pixel-bar-container" id="ping_ct_bars"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Rule 8: IP Quality Full-Width Card (12 Columns, 4:3:5 Internal Grid) -->
        <div class="ipcheck-card" id="ipcheck_card">
            <div class="card-header">
                <div class="card-header-left">
                    <span>📊</span>
                    <span>IP 质量体检与欺诈风控</span>
                </div>
                <span class="text-muted mono" style="font-size:0.74rem" id="ipc_time">更新时间: 刚刚</span>
            </div>

            <div class="ipcheck-info-row">
                <!-- Column 1: Basic Info (4 Columns) -->
                <div class="ipcheck-section">
                    <div class="ipcheck-section-title">🌍 基础网络信息</div>
                    <div class="ipcheck-row"><span class="ipcheck-label">IP 地址</span><span class="ipcheck-val mono" id="ipc_ip">37.114.48.47</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">ASN 编号</span><span class="ipcheck-val mono" id="ipc_asn">AS208643</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">所属组织</span><span class="ipcheck-val" id="ipc_org">ROETH &amp; BECK GbR</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">ISP 运营商</span><span class="ipcheck-val" id="ipc_isp">ROETH &amp; BECK GbR</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">国家/地区</span><span class="ipcheck-val" id="ipc_country">🇩🇪 德国</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">城市</span><span class="ipcheck-val" id="ipc_city">Berlin</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">时区</span><span class="ipcheck-val mono" id="ipc_tz">Europe/Berlin</span></div>
                </div>

                <!-- Column 2: IP Attributes (3 Columns) -->
                <div class="ipcheck-section">
                    <div class="ipcheck-section-title">🏷️ IP 属性与标记</div>
                    <div class="ipcheck-row"><span class="ipcheck-label">IP 类型</span><span class="ipcheck-val" id="ipc_type">-</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">代理 Proxy</span><span class="ipcheck-val" id="ipc_proxy">-</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">VPN 节点</span><span class="ipcheck-val" id="ipc_vpn">-</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">Tor 节点</span><span class="ipcheck-val" id="ipc_tor">-</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">IDC 机房</span><span class="ipcheck-val" id="ipc_hosting">-</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">蜂窝移动</span><span class="ipcheck-val" id="ipc_mobile">-</span></div>
                </div>

                <!-- Column 3: Risk Factor Analysis (5 Columns) -->
                <div class="ipcheck-section">
                    <div class="ipcheck-section-title">⚠️ 欺诈风险分析</div>
                    <div class="risk-score-display">
                        <span class="risk-score-num" id="ipc_risk_score">66</span>
                        <span class="badge-tag badge-tag-yes" id="ipc_risk_label">中高风险</span>
                    </div>

                    <!-- 4 Segmented Score Ribbon -->
                    <div class="risk-bar-segmented">
                        <div class="risk-segment active-green" id="rseg_1"></div>
                        <div class="risk-segment active-yellow" id="rseg_2"></div>
                        <div class="risk-segment active-orange" id="rseg_3"></div>
                        <div class="risk-segment" id="rseg_4"></div>
                    </div>

                    <!-- Factor Breakdown List -->
                    <div class="risk-factors-container">
                        <div class="risk-factor-row"><span>代理特征 (Proxy):</span><span id="rf_proxy" class="mono text-warning">已发现 (+20分)</span></div>
                        <div class="risk-factor-row"><span>IDC 机房特征:</span><span id="rf_hosting" class="mono text-warning">已发现 (+18分)</span></div>
                        <div class="risk-factor-row"><span>VPN 节点标记:</span><span id="rf_vpn" class="mono text-muted">未发现 (0分)</span></div>
                        <div class="risk-factor-row"><span>Tor 出口特征:</span><span id="rf_tor" class="mono text-muted">未发现 (0分)</span></div>
                    </div>

                    <!-- Low Saturation Background Advice Box -->
                    <div class="risk-advice-box" id="risk_advice_text">
                        系统建议：该 IP 具备机房代理网络特征，推荐用于常规网页浏览与流媒体解封，不建议用于强风控账号注册与支付业务。
                    </div>
                </div>
            </div>
        </div>

        <!-- Rule 9: Streaming & AI Full-Width Card (12 Columns, 4-Column 2-Row Tiles) -->
        <div class="streaming-card">
            <div class="card-header">
                <div class="card-header-left">
                    <span>🎬</span>
                    <span>流媒体 &amp; AI 服务解锁检测</span>
                </div>
                <div class="unlock-header-right">
                    <div class="filter-tabs-segmented">
                        <button class="tab-btn-seg active" onclick="filterUnlockTiles('all', this)">全部</button>
                        <button class="tab-btn-seg" onclick="filterUnlockTiles('unlocked', this)">已解锁</button>
                        <button class="tab-btn-seg" onclick="filterUnlockTiles('blocked', this)">未解锁</button>
                        <button class="tab-btn-seg" onclick="filterUnlockTiles('unknown', this)">异常</button>
                    </div>
                    <button class="btn-ctrl" id="ipcheck_btn" onclick="fetchIPCheck(true)" style="background:var(--accent); color:#000; font-weight:700">
                        <span id="ipcheck_spinner" style="display:none">🔄</span>
                        <span id="ipcheck_btn_text">重新体检</span>
                    </button>
                </div>
            </div>

            <div class="unlock-grid" id="unlock_grid">
                <!-- Populated by JS -->
            </div>
        </div>

        <!-- Rule 10: Diagnostic Console Full-Width Module (12 Columns) -->
        <div class="terminal-card" id="terminal_box">
            <div class="terminal-toolbar-two-tier">
                <!-- Tier 1 Toolbar -->
                <div class="toolbar-top-tier">
                    <div class="terminal-header-left">
                        <div class="terminal-dots">
                            <div class="win-dot win-red"></div>
                            <div class="win-dot win-yellow"></div>
                            <div class="win-dot win-green"></div>
                        </div>
                        <span style="font-size:0.82rem; font-weight:600; color:var(--text-secondary)">Diagnostic Console</span>
                    </div>

                    <div class="terminal-lookup-bar">
                        <input type="text" id="lookup_input" class="lookup-input-inline" placeholder="输入域名或 IP (如 github.com)..." />
                        <button id="lookup_btn" class="lookup-btn-inline">诊断</button>
                    </div>

                    <button class="chip-btn" onclick="toggleTerminalExpand()" title="展开/收起终端">⤢ 缩放</button>
                </div>

                <!-- Tier 2 Toolbar -->
                <div class="toolbar-bottom-tier">
                    <span style="font-size:0.72rem; color:var(--text-muted); margin-right:4px">快捷指令:</span>
                    <button class="chip-btn" onclick="quickRun('ipcheck')">IP 质量体检</button>
                    <button class="chip-btn" onclick="quickRun('acme status')">ACME 状态</button>
                    <button class="chip-btn" onclick="quickRun('acme issue')">申请 IP/域名证书</button>
                    <button class="chip-btn" onclick="quickRun('ping zj-cu-v4.ip.zstaticcdn.com')">Ping 联通</button>
                    <button class="chip-btn" onclick="quickRun('mtr 1.1.1.1')">MTR 路由</button>
                    <button class="chip-btn" onclick="quickRun('clear')">清屏</button>
                </div>
            </div>

            <div class="terminal-body" id="terminal_body">
                <pre id="cmd_output">System initialized. Type 'help' for available commands.
Try typing 'acme status' or 'acme issue 您的域名.com' or 'ping 8.8.8.8'
</pre>
                <div class="terminal-input-line">
                    <span class="prompt-text">root@{{ short_isp }}:~$</span>
                    <input type="text" id="cmd_input" class="terminal-input" placeholder="输入域名、IP 或命令开始诊断 (例如: ping 8.8.8.8 或 acme status)..." autofocus autocomplete="off" />
                </div>
            </div>
        </div>
    </div>

    <script>
    // Safe DOM Text & HTML Helpers
    function setElText(id, text) {
        const el = document.getElementById(id);
        if (el) el.textContent = (text !== null && text !== undefined) ? text : '-';
    }

    function setElHTML(id, html) {
        const el = document.getElementById(id);
        if (el) el.innerHTML = (html !== null && html !== undefined) ? html : '-';
    }

    // Theme switcher
    const themeSelect = document.getElementById('theme_select');
    themeSelect.addEventListener('change', e => {
        document.documentElement.setAttribute('data-theme', e.target.value);
        localStorage.setItem('console_theme', e.target.value);
    });
    const savedTheme = localStorage.getItem('console_theme') || 'neon';
    themeSelect.value = savedTheme;
    document.documentElement.setAttribute('data-theme', savedTheme);

    // Fullscreen Toggle
    function toggleFullScreen() {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen().catch(()=>{});
        } else {
            if (document.exitFullscreen) document.exitFullscreen().catch(()=>{});
        }
    }

    // Terminal Expansion Toggle
    function toggleTerminalExpand() {
        const box = document.getElementById('terminal_box');
        box.classList.toggle('expanded');
    }

    // Copy Egress IP to Clipboard
    let rawEgressIP = '37.114.48.47';
    function copyIP() {
        if (!rawEgressIP) return;
        navigator.clipboard.writeText(rawEgressIP).then(() => {
            const btn = document.querySelector('.btn-copy');
            if (btn) {
                const orig = btn.textContent;
                btn.textContent = '✅ 已复制';
                setTimeout(() => btn.textContent = orig, 1800);
            }
        }).catch(()=>{});
    }

    // Dynamic Interval Control
    let refreshTimer = null;
    let pingTimer = null;
    const intervalSelect = document.getElementById('interval_select');

    function updateTimers() {
        const ms = parseInt(intervalSelect.value, 10);
        if (refreshTimer) clearInterval(refreshTimer);
        if (pingTimer) clearInterval(pingTimer);
        if (ms > 0) {
            fetchStats();
            fetchPings();
            refreshTimer = setInterval(fetchStats, ms);
            pingTimer = setInterval(fetchPings, ms);
        }
    }
    intervalSelect.addEventListener('change', updateTimers);

    // Metrics progress bars
    function updateProgress(id, pct) {
        const valEl = document.getElementById(id + '_val');
        const barEl = document.getElementById(id + '_bar');
        const badgeEl = document.getElementById(id + '_badge');

        if (valEl) valEl.textContent = `${pct.toFixed(1)}%`;
        if (barEl) {
            barEl.style.width = `${Math.min(100, Math.max(0, pct))}%`;
            barEl.className = 'progress-fill';
            if (badgeEl) {
                if (pct >= 85) {
                    barEl.classList.add('danger');
                    badgeEl.className = 'metric-badge badge-danger';
                    badgeEl.textContent = '告警';
                } else if (pct >= 60) {
                    barEl.classList.add('warn');
                    badgeEl.className = 'metric-badge badge-warn';
                    badgeEl.textContent = '预警';
                } else {
                    badgeEl.className = 'metric-badge badge-normal';
                    badgeEl.textContent = '正常';
                }
            }
        }
    }

    // Fetch ACME SSL Status
    async function fetchAcmeStatus() {
        try {
            const res = await fetch('/acme/status');
            const data = await res.json();
            const badge = document.getElementById('acme_badge');
            if (data.has_cert) {
                if (badge) {
                    badge.innerHTML = `<span class="pulse-dot"></span> 🔒 SSL 正常 (${data.days_left}天)`;
                }
                setElText('acme_val', `${data.domain} (${data.days_left}天后到期)`);
            } else {
                if (badge) {
                    badge.innerHTML = `<span class="pulse-dot dot-warning"></span> 🔓 HTTP 运行中`;
                }
                setElText('acme_val', `未申请 (支持 'acme issue' 签发)`);
            }
        } catch(e) {}
    }

    // Fetch Stats & Update Executive Summary (Rule 4: Public IP Fix)
    async function fetchStats() {
        try {
            const res = await fetch('/stats');
            const data = await res.json();
            if (data.cpu !== null) updateProgress('cpu', data.cpu);
            if (data.memory !== null) updateProgress('memory', data.memory);
            if (data.disk !== null) updateProgress('disk', data.disk);

            setElText('cuptime', data.container_uptime);
            setElText('huptime', data.host_uptime);
            setElText('cpu_cores', data.cores ? `${data.cores} 核` : '-');
            setElText('load_val', `Load: ${data.load || 'N/A'}`);
            setElText('disk_io', data.disk_io);
            setElText('net_io', data.net_io);
            
            // Extract Public IP vs Container LAN IP
            let pubIP = '37.114.48.47';
            let lanIP = '172.17.0.2';
            if (data.ip) {
                const match = data.ip.match(/公网\s*(\d+\.\d+\.\d+\.\d+)/);
                if (match) {
                    pubIP = match[1];
                    lanIP = data.ip.split(' ')[0];
                } else if (!data.ip.startsWith('172.') && !data.ip.startsWith('10.')) {
                    pubIP = data.ip.split(' ')[0];
                }
            }
            rawEgressIP = pubIP;

            // Summary Card 2: Public Egress IP Display
            setElText('sum_ip_val', pubIP);
            setElText('sum_ip_desc', `${data.hostname || '德国 · ROETH & BECK GbR'}`);

            // System Telemetry list split display
            setElText('public_ip_val', pubIP);
            setElText('lan_ip_val', lanIP);

            const cip = data.client_ip ? `${data.client_ip} [${data.client_isp || '未知'}]` : '局域网';
            setElText('client_ip_val', cip);

            fetchAcmeStatus();
        } catch (e) {
            console.error("Failed to fetch stats:", e);
        }
    }

    // Fetch Host details
    async function fetchHost() {
        try {
            const res = await fetch('/host');
            const data = await res.json();
            const osVal = data.system ? `${data.system} ${data.release || ''}` : '-';
            const osEl = document.getElementById('os_val');
            if (osEl) {
                osEl.textContent = osVal;
                osEl.title = osVal;
            }
            setElText('arch_val', data.machine);
            setElText('mem_total_val', data.total_memory);
            setElText('disk_total_val', data.total_disk);
        } catch(e) {}
    }

    // Latency Ping History & Sparkline Calculation (Rule 7: Sci-Fi Blue Sparklines)
    const pingHistory = { client_ping: [], ping_cu: [], ping_cm: [], ping_ct: [] };
    const MAX_BARS = 40;

    function renderPixelBars(key) {
        const container = document.getElementById(key + '_bars');
        if (!container) return;
        const rawHistory = pingHistory[key];
        if (!rawHistory.length) return;

        container.innerHTML = '';
        for (let i = 0; i < MAX_BARS; i++) {
            const bar = document.createElement('div');
            bar.className = 'pixel-bar';
            const val = rawHistory[i];
            if (val === undefined) {
                bar.classList.add('px-empty');
            } else if (val === null) {
                bar.classList.add('px-timeout');
            } else {
                const heightPct = Math.min(100, Math.max(12, (val / 350) * 100));
                bar.style.height = `${heightPct}%`;
                if (val < 80) bar.classList.add('px-cyan');
                else if (val < 160) bar.classList.add('px-yellow');
                else if (val < 250) bar.classList.add('px-orange');
                else bar.classList.add('px-red');
            }
            container.appendChild(bar);
        }
    }

    function updatePingUI(key, ms) {
        const history = pingHistory[key];
        history.push(ms);
        if (history.length > MAX_BARS) history.shift();

        const valEl = document.getElementById(key + '_val');
        const statEl = document.getElementById(key + '_stat');
        const trendEl = document.getElementById(key + '_trend');

        const validSamples = history.filter(v => v !== null && v !== undefined);

        if (valEl) {
            if (ms === null || ms === undefined) {
                valEl.textContent = '超时';
                valEl.style.color = 'var(--danger)';
            } else {
                valEl.textContent = `${ms.toFixed(1)} ms`;
                valEl.style.color = ms < 80 ? 'var(--info)' : ms < 160 ? 'var(--warning)' : ms < 250 ? 'var(--orange)' : 'var(--danger)';
            }
        }

        if (statEl && validSamples.length) {
            const avg = validSamples.reduce((a,b)=>a+b,0) / validSamples.length;
            const min = Math.min(...validSamples);
            const jitter = Math.abs(ms - avg);
            statEl.textContent = `均值:${avg.toFixed(0)}ms | Min:${min.toFixed(0)}ms | 抖动:±${jitter.toFixed(0)}ms`;
        }

        if (trendEl && validSamples.length >= 3) {
            const firstHalf = validSamples.slice(0, Math.floor(validSamples.length / 2));
            const secondHalf = validSamples.slice(Math.floor(validSamples.length / 2));
            const avgOld = firstHalf.reduce((a,b)=>a+b,0) / firstHalf.length;
            const avgNew = secondHalf.reduce((a,b)=>a+b,0) / secondHalf.length;
            const diff = avgNew - avgOld;

            if (diff <= -2.0) {
                trendEl.textContent = `↓ 较初始 ${diff.toFixed(1)}ms`;
                trendEl.style.color = 'var(--success)';
            } else if (diff >= 2.0) {
                trendEl.textContent = `↑ 较初始 +${diff.toFixed(1)}ms`;
                trendEl.style.color = 'var(--orange)';
            } else {
                trendEl.textContent = '~ 平稳';
                trendEl.style.color = 'var(--text-muted)';
            }
        }

        renderPixelBars(key);
    }

    async function fetchPings() {
        try {
            const res = await fetch('/pings');
            const data = await res.json();
            updatePingUI('client_ping', data.client_ping);
            updatePingUI('ping_cu', data.ping_cu);
            updatePingUI('ping_cm', data.ping_cm);
            updatePingUI('ping_ct', data.ping_ct);

            // Update Summary Cards 1 & 3
            const pings = [data.ping_cu, data.ping_cm, data.ping_ct].filter(v => v !== null && v !== undefined);
            if (pings.length) {
                const avgPing = pings.reduce((a,b)=>a+b,0) / pings.length;
                setElHTML('sum_ping_val', `${avgPing.toFixed(0)} <span class="summary-unit">ms</span>`);

                const statusEl = document.getElementById('sum_net_status');
                const descEl = document.getElementById('sum_net_desc');
                const dotEl = document.getElementById('sum_net_dot');

                if (avgPing < 150) {
                    if (statusEl) { statusEl.textContent = '健康'; statusEl.className = 'summary-value text-success'; }
                    if (descEl) descEl.textContent = `平均 TCP 延迟 ${avgPing.toFixed(0)}ms · 线路良好`;
                    if (dotEl) dotEl.className = 'pulse-dot';
                } else if (avgPing < 250) {
                    if (statusEl) { statusEl.textContent = '良好'; statusEl.className = 'summary-value text-warning'; }
                    if (descEl) descEl.textContent = `平均 TCP 延迟 ${avgPing.toFixed(0)}ms · 抖动正常`;
                    if (dotEl) dotEl.className = 'pulse-dot dot-warning';
                } else {
                    if (statusEl) { statusEl.textContent = '较慢'; statusEl.className = 'summary-value text-orange'; }
                    if (descEl) descEl.textContent = `平均 TCP 延迟 ${avgPing.toFixed(0)}ms · 跨境链路延迟偏高`;
                    if (dotEl) dotEl.className = 'pulse-dot dot-orange';
                }
            }
        } catch (e) {
            console.error("Failed to fetch pings:", e);
        }
    }

    // Quick Lookup Form
    const lookupBtn = document.getElementById('lookup_btn');
    const lookupInput = document.getElementById('lookup_input');

    async function doLookup(target) {
        if (!target) return;
        lookupBtn.textContent = '查询中...';
        try {
            const res = await fetch(`/pinginfo?url=${encodeURIComponent(target)}`);
            if (!res.ok) throw new Error("查询失败");
            const data = await res.json();
            appendOutput(`[网络诊断结果]\n  目标: ${data.host || target}\n  解析 IP: ${data.ip || 'N/A'}\n  运营商/位置: ${data.isp || '未知'}\n  TCP 延迟: ${data.ping !== null ? data.ping.toFixed(1) + ' ms' : '超时'}`);
        } catch (e) {
            appendOutput('诊断出错: ' + e.message);
        } finally {
            lookupBtn.textContent = '诊断';
        }
    }

    lookupBtn.addEventListener('click', () => doLookup(lookupInput.value.trim()));
    lookupInput.addEventListener('keydown', e => { if (e.key === 'Enter') doLookup(lookupInput.value.trim()); });

    // Interactive Terminal Shell
    const PROMPT = 'root@{{ short_isp }}:~$';
    const outputEl = document.getElementById('cmd_output');
    const inputEl = document.getElementById('cmd_input');
    const terminalBody = document.getElementById('terminal_body');
    const terminalBox = document.getElementById('terminal_box');

    let cmdHistory = [];
    let historyIdx = -1;
    let currentSource = null;

    terminalBox.addEventListener('click', (e) => {
        if (!e.target.closest('button') && !e.target.closest('input')) {
            inputEl.focus();
        }
    });

    function appendOutput(text) {
        outputEl.insertAdjacentText('beforeend', text + '\n');
        terminalBody.scrollTop = terminalBody.scrollHeight;
    }

    function runCommand(cmd, target = '', args = '') {
        if (currentSource) currentSource.close();
        const commandText = [cmd, target, args].filter(Boolean).join(' ');
        appendOutput(`${PROMPT} ${commandText}`);

        let url = `/run/${cmd}`;
        const params = [];
        if (target) params.push(`target=${encodeURIComponent(target)}`);
        if (args) params.push(`args=${encodeURIComponent(args)}`);
        if (params.length) url += `?${params.join('&')}`;

        currentSource = new EventSource(url);
        currentSource.onmessage = e => {
            const data = e.data;
            if (!data.startsWith('[exit')) {
                appendOutput(data);
            } else {
                currentSource.close();
                currentSource = null;
            }
        };
        currentSource.onerror = () => {
            appendOutput('Command execution failed or aborted.');
            if (currentSource) currentSource.close();
            currentSource = null;
        };
    }

    function quickRun(cmdStr) {
        inputEl.value = cmdStr;
        handleCommand(cmdStr);
    }

    function handleCommand(text) {
        text = text.trim();
        if (!text) return;
        cmdHistory.push(text);
        historyIdx = cmdHistory.length;

        const [cmd, ...args] = text.split(/\s+/);
        switch (cmd.toLowerCase()) {
            case 'clear':
            case 'cls':
                outputEl.textContent = '';
                break;
            case 'ping':
            case 'mtr':
                if (args.length) {
                    runCommand(cmd.toLowerCase(), args.join(' '));
                } else {
                    appendOutput(`${PROMPT} ${text}\nError: Missing target host/IP.`);
                }
                break;
            case 'lookup':
                if (args.length) {
                    appendOutput(`${PROMPT} ${text}\nQuerying ${args[0]}...`);
                    doLookup(args[0]);
                } else {
                    appendOutput(`${PROMPT} ${text}\nError: Missing domain or IP.`);
                }
                break;
            case 'acme':
                const sub = args[0] ? args[0].toLowerCase() : 'status';
                if (sub === 'status') {
                    appendOutput(`${PROMPT} ${text}\nQuerying ACME SSL Certificate Status...`);
                    fetch('/acme/status').then(r=>r.json()).then(data => {
                        appendOutput(`[ACME Status]\n  Status: ${data.status}\n  Domain/IP: ${data.domain || 'None'}\n  Days Left: ${data.days_left}\n  Issuer: ${data.issuer || 'N/A'}\n  Expires On: ${data.expires_on || 'N/A'}`);
                    });
                } else if (sub === 'issue') {
                    const targetHost = args[1] || '';
                    appendOutput(`${PROMPT} ${text}\nInitiating ACME Certificate issuance... Please wait...`);
                    fetch(`/acme/issue${targetHost ? '?target=' + encodeURIComponent(targetHost) : ''}`).then(r=>r.json()).then(data => {
                        appendOutput(`[ACME Issue Result]\n  Success: ${data.success}\n  Message: ${data.message}`);
                        fetchAcmeStatus();
                    }).catch(err => appendOutput(`ACME issue error: ${err.message}`));
                } else if (sub === 'renew') {
                    appendOutput(`${PROMPT} ${text}\nTriggering ACME Certificate renewal...`);
                    fetch('/acme/renew').then(r=>r.json()).then(data => {
                        appendOutput(`[ACME Renew Result]\n  Success: ${data.success}\n  Message: ${data.message}`);
                        fetchAcmeStatus();
                    }).catch(err => appendOutput(`ACME renew error: ${err.message}`));
                } else {
                    appendOutput(`${PROMPT} ${text}\nUsage: acme <status|issue|renew> [domain_or_ip]`);
                }
                break;
            case 'ipcheck':
                appendOutput(`${PROMPT} ${text}\nRunning IP Quality Check... Please wait...`);
                fetchIPCheck(true);
                break;
            case 'help':
                appendOutput(`${PROMPT} ${text}\n` +
                    'Available Cyber Commands:\n' +
                    '  ipcheck             - Run IP quality & streaming unlock check\n' +
                    '  acme status         - Check ACME SSL certificate status\n' +
                    '  acme issue [domain] - Issue free ACME SSL certificate for IP/Domain\n' +
                    '  acme renew          - Force renew ACME SSL certificate\n' +
                    '  ping <host>         - Run ping to target host/IP\n' +
                    '  mtr <host>          - Run MTR traceroute to target\n' +
                    '  lookup <host>       - Query IP, ISP, and latency info\n' +
                    '  clear / cls         - Clear terminal screen\n' +
                    '  stats               - Refresh system metrics\n' +
                    '  theme <neon|matrix|cyberpunk> - Change UI visual theme\n' +
                    '  help                - Show this help message\n');
                break;
            case 'stats':
                appendOutput(`${PROMPT} ${text}`);
                fetchStats();
                appendOutput('System metrics refreshed.');
                break;
            case 'theme':
                if (args.length && ['matrix', 'cyberpunk', 'neon'].includes(args[0])) {
                    document.documentElement.setAttribute('data-theme', args[0]);
                    themeSelect.value = args[0];
                    localStorage.setItem('console_theme', args[0]);
                    appendOutput(`${PROMPT} ${text}\nTheme changed to ${args[0]}`);
                } else {
                    appendOutput(`${PROMPT} ${text}\nUsage: theme <neon|matrix|cyberpunk>`);
                }
                break;
            default:
                appendOutput(`${PROMPT} ${text}\nCommand not found: '${cmd}'. Type 'help' for commands.`);
        }
        inputEl.value = '';
    }

    inputEl.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            handleCommand(inputEl.value);
        } else if (e.key === 'ArrowUp') {
            if (cmdHistory.length && historyIdx > 0) {
                historyIdx--;
                inputEl.value = cmdHistory[historyIdx];
            }
            e.preventDefault();
        } else if (e.key === 'ArrowDown') {
            if (cmdHistory.length && historyIdx < cmdHistory.length - 1) {
                historyIdx++;
                inputEl.value = cmdHistory[historyIdx];
            } else {
                historyIdx = cmdHistory.length;
                inputEl.value = '';
            }
            e.preventDefault();
        }
    });

    // IP Quality Check & Official Brand Vector SVGs
    const MEDIA_ICONS = {
        'Netflix': `<svg viewBox="0 0 24 24" width="18" height="18" style="vertical-align:middle; flex-shrink:0;"><path fill="#E50914" d="M5.398 0v24h4.423V11.892l4.809 12.108h4.403V0h-4.423v12.108L9.801 0z"/></svg>`,
        'YouTube Premium': `<svg viewBox="0 0 24 24" width="18" height="18" style="vertical-align:middle; flex-shrink:0;"><path fill="#FF0000" d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/></svg>`,
        'Disney+': `<svg viewBox="0 0 24 24" width="18" height="18" style="vertical-align:middle; flex-shrink:0;"><path fill="#00A8E1" d="M22.25 15.63c-.35.12-.9.2-1.5.2-1.78 0-2.88-.86-2.88-2.3 0-1.8 1.63-3.23 3.95-3.23.63 0 1.15.08 1.5.18v-.43c0-1.45-1.07-2.3-2.83-2.3-1.12 0-2.35.33-3.17.8l-.55-1.25c1.02-.6 2.58-.98 4.02-.98 2.7 0 4.3 1.35 4.3 3.73v5.18c0 .9.08 1.73.28 2.45h-1.88c-.12-.4-.2-.95-.24-2.05zM12 2a10 10 0 1010 10A10 10 0 0012 2zm.2 13.8a2.6 2.6 0 01-1.8.6c-1.4 0-2.2-.8-2.2-1.9 0-1.5 1.3-2.3 3.4-2.3h.6v3.6z"/></svg>`,
        'TikTok': `<svg viewBox="0 0 24 24" width="18" height="18" style="vertical-align:middle; flex-shrink:0;"><path fill="#25F4EE" d="M19.589 6.686a4.793 4.793 0 0 1-3.77-4.245V2h-3.445v13.672a2.896 2.896 0 0 1-5.201 1.743 2.895 2.895 0 0 1 3.313-4.508V9.38a6.34 6.34 0 0 0-1.077-.091 6.34 6.34 0 1 0 6.342 6.34V8.756a8.214 8.214 0 0 0 4.838 1.558V6.869a4.838 4.838 0 0 1-1.006-.183z"/><path fill="#FE2C55" d="M16.25 5.5a5.5 5.5 0 0 0 4.5 1.5v-1.8a3.7 3.7 0 0 1-3-1.2V2h-1.5v13.5a1.5 1.5 0 1 1-3-1.5v-1.8a3.3 3.3 0 1 0 3.3 3.3V5.5z"/></svg>`,
        'ChatGPT': `<svg viewBox="0 0 24 24" width="18" height="18" style="vertical-align:middle; flex-shrink:0;"><path fill="#10A37F" d="M22.28 9.82a5.98 5.98 0 0 0-.52-4.91 6.05 6.05 0 0 0-6.51-2.9 6.07 6.07 0 0 0-4.63-2.07 6.06 6.06 0 0 0-5.77 4.18 6.05 6.05 0 0 0-4.14 2.99 6.05 6.05 0 0 0 .74 7.12 5.98 5.98 0 0 0 .52 4.91 6.05 6.05 0 0 0 6.52 2.9 6.05 6.05 0 0 0 4.62 2.07 6.06 6.06 0 0 0 5.77-4.18 6.05 6.05 0 0 0 4.14-2.99 6.05 6.05 0 0 0-.74-7.12zm-9.33 11.2a4.42 4.42 0 0 1-2.58-.83l.14-.08 4.25-2.45a.82.82 0 0 0 .41-.71v-6l1.78 1.03a.08.08 0 0 1 .05.06v5.03a4.43 4.43 0 0 1-4.05 3.95zm-8.4-4.85a4.43 4.43 0 0 1-.5-2.65l.15.08 4.25 2.45a.82.82 0 0 0 .82 0l5.2-3v2.06a.08.08 0 0 1-.03.07l-4.35 2.51a4.43 4.43 0 0 1-5.54-1.52zm-1.12-9.7a4.43 4.43 0 0 1 2.08-1.83v.17l0 4.91a.82.82 0 0 0 .41.71l5.2 3-1.78 1.03a.08.08 0 0 1-.08 0l-4.35-2.51a4.43 4.43 0 0 1-1.48-5.48zm14.8 2.2l-5.2-3 1.78-1.03a.08.08 0 0 1 .08 0l4.35 2.51a4.43 4.43 0 0 1 1.48 5.48 4.43 4.43 0 0 1-2.08 1.83v-.17l0-4.91a.82.82 0 0 0-.41-.71zm1.62 6.55l-.15-.08-4.25-2.45a.82.82 0 0 0-.82 0l-5.2 3v-2.06a.08.08 0 0 1 .03-.07l4.35-2.51a4.43 4.43 0 0 1 5.54 1.52 4.43 4.43 0 0 1 .5 2.65zm-9.35-4.47l-2.41-1.39 2.41-1.39 2.41 1.39-2.41 1.39z"/></svg>`,
        'Claude': `<svg viewBox="0 0 24 24" width="18" height="18" style="vertical-align:middle; flex-shrink:0;"><path fill="#D97757" d="M12 2L14.5 8.5L21 6.5L16.5 12L22 15.5L15 16.5L16.5 23L12 17.5L7.5 23L9 16.5L2 15.5L7.5 12L3 6.5L9.5 8.5L12 2Z"/></svg>`,
        'Spotify': `<svg viewBox="0 0 24 24" width="18" height="18" style="vertical-align:middle; flex-shrink:0;"><path fill="#1DB954" d="M12 0C5.376 0 0 5.377 0 12s5.376 12 12 12 12-5.377 12-12S18.624 0 12 0zm5.521 17.341c-.217.357-.68.471-1.036.251-2.836-1.733-6.408-2.126-10.617-1.165-.403.092-.807-.156-.898-.558-.093-.404.156-.807.558-.899 4.607-1.052 8.547-.604 11.742 1.336.357.218.472.68.251 1.035zm1.472-3.272c-.273.443-.855.584-1.298.311-3.245-1.995-8.192-2.573-12.03-1.408-.497.151-1.022-.132-1.174-.629-.151-.497.132-1.022.629-1.174 4.385-1.332 9.851-.69 13.562 1.599.444.272.584.855.311 1.298zm.126-3.411c-3.893-2.312-10.319-2.525-14.072-1.385-.598.181-1.231-.157-1.413-.755-.181-.598.158-1.232.756-1.413 4.309-1.308 11.4-1.05 15.892 1.616.538.319.717 1.018.399 1.556-.319.539-1.018.718-1.562.381z"/></svg>`,
        'Amazon Prime': `<svg viewBox="0 0 24 24" width="18" height="18" style="vertical-align:middle; flex-shrink:0;"><path fill="#00A8E1" d="M14.5 12.8c-1.8 0-3.3-.6-4.7-1.7l1.1-1.3c1.1.9 2.3 1.4 3.6 1.4 1.2 0 1.9-.5 1.9-1.2 0-.8-.7-1.2-2.3-1.7-2.3-.7-3.6-1.6-3.6-3.4 0-2.1 1.7-3.5 4.3-3.5 1.6 0 3 .5 4.1 1.3l-1.1 1.3c-.9-.7-1.9-1-3-1-1.2 0-1.8.5-1.8 1.1 0 .7.6 1.1 2.2 1.6 2.5.8 3.7 1.7 3.7 3.5 0 2.2-1.7 3.6-4.4 3.6zm-1.8 6c-4.4 0-8.5-1.8-11.4-4.8-.3-.3-.1-.7.3-.6 3.6 1.3 7.6 1.9 11.5 1.5 3.8-.4 7.4-1.7 10.4-3.9.4-.3.8.1.5.5-3 2.9-7.2 4.9-11.3 7.3z"/></svg>`
    };

    let cachedMediaData = [];
    let currentUnlockFilter = 'all';

    function filterUnlockTiles(filter, btnEl) {
        currentUnlockFilter = filter;
        if (btnEl) {
            document.querySelectorAll('.filter-tabs-segmented .tab-btn-seg').forEach(b => b.classList.remove('active'));
            btnEl.classList.add('active');
        }
        renderUnlockGrid(cachedMediaData);
    }

    // Rule 9: 4-Column 2-Row Tile Renderer
    function renderUnlockGrid(mediaList) {
        cachedMediaData = mediaList || [];
        const grid = document.getElementById('unlock_grid');
        if (!grid) return;
        grid.innerHTML = '';

        const filtered = cachedMediaData.filter(m => {
            if (currentUnlockFilter === 'unlocked') return m.status === 'unlocked';
            if (currentUnlockFilter === 'blocked') return m.status === 'blocked';
            if (currentUnlockFilter === 'unknown') return m.status !== 'unlocked' && m.status !== 'blocked';
            return true;
        });

        if (!filtered.length) {
            grid.innerHTML = `<div style="grid-column:span 4; text-align:center; padding:14px; color:var(--text-muted); font-size:0.78rem">无匹配的服务解锁记录</div>`;
            return;
        }

        filtered.forEach(m => {
            const icon = MEDIA_ICONS[m.name] || '🌐';
            let badgeClass, badgeText;
            if (m.status === 'unlocked') { badgeClass = 'unlocked'; badgeText = '已解锁'; }
            else if (m.status === 'blocked') { badgeClass = 'blocked'; badgeText = '未解锁'; }
            else { badgeClass = 'unknown'; badgeText = '检测异常'; }
            const regionText = m.region ? ` (${m.region})` : '';

            grid.innerHTML += `
                <div class="unlock-tile-capsule">
                    <div class="unlock-tile-top">
                        <span style="display:flex; align-items:center; gap:8px">${icon} ${m.name}</span>
                    </div>
                    <div class="unlock-tile-bottom">
                        <span class="unlock-badge ${badgeClass}">${badgeText}</span>
                        <span class="text-muted">${regionText || '全球/原生'}</span>
                    </div>
                </div>`;
        });
    }

    function renderIPCheckResult(data) {
        const b = data.basic || {};
        const r = data.risk || {};

        // Basic info
        setElText('ipc_ip', b.ip || '37.114.48.47');
        setElText('ipc_asn', b.asn || 'AS208643');
        setElText('ipc_org', b.org || 'ROETH & BECK GbR');
        setElText('ipc_isp', b.isp || 'ROETH & BECK GbR');
        const flag = b.countryCode ? String.fromCodePoint(...[...b.countryCode.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) + ' ' : '';
        setElText('ipc_country', flag + (b.country || '德国'));
        setElText('ipc_city', b.city || 'Berlin');
        setElText('ipc_tz', b.timezone || 'Europe/Berlin');

        // IP type badge
        const typeLabel = r.ip_type_label || '机房 IDC';
        let typeClass = 'badge-tag-yes';
        if (r.is_tor || (r.risk_score && r.risk_score > 80)) typeClass = 'badge-tag-high';
        else if (!r.is_hosting && !r.is_proxy) typeClass = 'badge-tag-no';
        setElHTML('ipc_type', `<span class="badge-tag ${typeClass}">${typeLabel}</span>`);

        // Risk factor badges
        const factorHTML = (val, highRisk=false) => {
            if (!val) return '<span class="badge-tag badge-tag-no">否</span>';
            return highRisk ? '<span class="badge-tag badge-tag-high">是 (高危)</span>' : '<span class="badge-tag badge-tag-yes">是</span>';
        };

        setElHTML('ipc_proxy', factorHTML(r.is_proxy));
        setElHTML('ipc_vpn', factorHTML(r.is_vpn));
        setElHTML('ipc_tor', factorHTML(r.is_tor, true));
        setElHTML('ipc_hosting', factorHTML(r.is_hosting));
        setElHTML('ipc_mobile', factorHTML(r.is_mobile));

        // Risk Score
        const score = r.risk_score || 66;
        setElText('ipc_risk_score', score);

        // Summary Card 4 update
        const sumRiskVal = document.getElementById('sum_risk_val');
        const sumRiskDesc = document.getElementById('sum_risk_desc');
        if (sumRiskVal) {
            sumRiskVal.innerHTML = `${score} <span class="summary-unit">/ 100</span>`;
            if (score <= 30) sumRiskVal.className = 'summary-value text-success mono';
            else if (score <= 60) sumRiskVal.className = 'summary-value text-warning mono';
            else if (score <= 80) sumRiskVal.className = 'summary-value text-orange mono';
            else sumRiskVal.className = 'summary-value text-danger mono';
        }
        if (sumRiskDesc) sumRiskDesc.textContent = `${r.risk_label || '中高风险'} · Scamalytics`;

        const riskBadge = document.getElementById('ipc_risk_label');
        if (riskBadge) {
            riskBadge.textContent = r.risk_label || '中高风险';
            if (score <= 30) riskBadge.className = 'badge-tag badge-tag-no';
            else if (score <= 60) riskBadge.className = 'badge-tag badge-tag-yes';
            else riskBadge.className = 'badge-tag badge-tag-high';
        }

        // 4 Segment Ribbon
        const s1 = document.getElementById('rseg_1');
        const s2 = document.getElementById('rseg_2');
        const s3 = document.getElementById('rseg_3');
        const s4 = document.getElementById('rseg_4');
        if (s1 && s2 && s3 && s4) {
            s1.className = 'risk-segment' + (score > 0 ? ' active-green' : '');
            s2.className = 'risk-segment' + (score > 30 ? ' active-yellow' : '');
            s3.className = 'risk-segment' + (score > 60 ? ' active-orange' : '');
            s4.className = 'risk-segment' + (score > 80 ? ' active-red' : '');
        }

        // Factor Breakdown List
        setElHTML('rf_proxy', r.is_proxy ? '<span class="text-warning">已发现 (+20分)</span>' : '<span class="text-muted">未发现 (0分)</span>');
        setElHTML('rf_hosting', r.is_hosting ? '<span class="text-warning">已发现 (+18分)</span>' : '<span class="text-muted">未发现 (0分)</span>');
        setElHTML('rf_vpn', r.is_vpn ? '<span class="text-warning">已发现 (+16分)</span>' : '<span class="text-muted">未发现 (0分)</span>');
        setElHTML('rf_tor', r.is_tor ? '<span class="text-danger">已发现 (+35分)</span>' : '<span class="text-muted">未发现 (0分)</span>');

        const adviceEl = document.getElementById('risk_advice_text');
        if (adviceEl) {
            if (score <= 30) adviceEl.textContent = '系统建议：洁净原生 IP，具备良好信誉，推荐用于各类高风控业务及流媒体解封。';
            else if (score <= 75) adviceEl.textContent = '系统建议：该 IP 具备机房代理网络特征，推荐用于常规网页浏览与流媒体解封，不建议用于强风控账号注册与支付业务。';
            else adviceEl.textContent = '系统建议：具备高风险代理或 Tor 节点特征，不建议用于敏感账号操作及支付交互。';
        }

        setElText('ipc_time', data.timestamp ? `更新时间: ${data.timestamp}` : '更新时间: 刚刚');

        // Render Streaming Unlock Tiles
        renderUnlockGrid(data.media || []);
    }

    async function fetchIPCheck(force) {
        const btn = document.getElementById('ipcheck_btn');
        const spinner = document.getElementById('ipcheck_spinner');
        const btnText = document.getElementById('ipcheck_btn_text');
        if (btn) btn.disabled = true;
        if (spinner) spinner.style.display = 'inline-block';
        if (btnText) btnText.textContent = '检测中...';
        try {
            const url = force ? '/ipcheck?force=1' : '/ipcheck';
            const res = await fetch(url);
            const data = await res.json();
            if (data.error) { alert('检测失败: ' + data.error); return; }
            renderIPCheckResult(data);
        } catch(e) {
            alert('IP 质量检测请求失败: ' + e.message);
        } finally {
            btn.disabled = false;
            spinner.style.display = 'none';
            btnText.textContent = '重新检测';
        }
    }

    // Initialize
    fetchStats();
    fetchHost();
    fetchPings();
    fetchIPCheck(); // Default fetch on page load
    updateTimers();
    </script>
</body>
</html>
"""

@app.route("/.well-known/acme-challenge/<path:filename>")
def acme_challenge_file(filename):
    try:
        challenge_dir = acme_manager.CHALLENGE_DIR
        target_file = challenge_dir / filename
        if target_file.exists() and target_file.is_file():
            content = target_file.read_text(encoding="utf-8", errors="ignore")
            logger.info("Serving ACME HTTP-01 challenge file for %s", filename)
            return Response(content, mimetype="text/plain")
        logger.warning("ACME challenge file not found: %s (path: %s)", filename, target_file)
    except Exception as e:
        logger.exception("Error serving ACME challenge file: %s", e)
    return "Challenge file not found", 404


@app.route("/")
def index():
    ensure_isp_info()
    hostname = ISP_FULL_NAME or socket.gethostname()
    short_isp = ISP_SHORT_NAME or socket.gethostname()
    return render_template_string(TEMPLATE, hostname=hostname, short_isp=short_isp)


@app.route("/stats")
def stats():
    ensure_isp_info()
    try:
        cpu = psutil.cpu_percent(interval=None)
    except Exception:
        cpu = None
    try:
        mem = psutil.virtual_memory().percent
    except Exception:
        mem = None
    try:
        disk = psutil.disk_usage("/").percent
    except Exception:
        disk = None
    container_uptime = int((datetime.now() - start_time).total_seconds())
    host_uptime = int((datetime.now() - host_boot_time).total_seconds())
    hostname = ISP_FULL_NAME or socket.gethostname()
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "N/A"
    
    public_ip = get_public_ip()
    if ip == "N/A" and public_ip == "N/A":
        ip_display = None
    else:
        ip_display = f"{ip} (公网 {public_ip})"
        
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    if client_ip not in CLIENT_ISP_CACHE:
        CLIENT_ISP_CACHE[client_ip] = query_isp(client_ip) if client_ip else None
    client_isp = CLIENT_ISP_CACHE.get(client_ip)
    try:
        cores = psutil.cpu_count()
    except Exception:
        cores = None
    try:
        load1, load5, load15 = os.getloadavg()
        load = f"{load1:.2f}, {load5:.2f}, {load15:.2f}"
    except Exception:
        load = None
    try:
        dio = psutil.disk_io_counters()
        disk_io = f"{humanize_bytes(dio.read_bytes)}/{humanize_bytes(dio.write_bytes)}"
    except Exception:
        disk_io = None
    global _last_net, _last_time
    try:
        nio = psutil.net_io_counters()
        if _last_net is None:
            _last_net, _last_time = nio, datetime.now()
            net_io = f"0.0B/s ({humanize_bytes(nio.bytes_sent)}) / 0.0B/s ({humanize_bytes(nio.bytes_recv)})"
        else:
            now = datetime.now()
            interval = (now - _last_time).total_seconds() or 1
            up_speed = (nio.bytes_sent - _last_net.bytes_sent) / interval
            down_speed = (nio.bytes_recv - _last_net.bytes_recv) / interval
            _last_net, _last_time = nio, now
            net_io = (
                f"{humanize_bytes(up_speed)}/s ({humanize_bytes(nio.bytes_sent)}) / "
                f"{humanize_bytes(down_speed)}/s ({humanize_bytes(nio.bytes_recv)})"
            )
    except Exception:
        net_io = None
    return jsonify(
        cpu=cpu,
        memory=mem,
        disk=disk,
        container_uptime=humanize(container_uptime),
        host_uptime=humanize(host_uptime),
        hostname=hostname,
        ip=ip_display,
        client_ip=client_ip,
        cores=cores,
        load=load,
        disk_io=disk_io,
        net_io=net_io,
        client_isp=client_isp,
    )


@app.route("/host")
def host():
    try:
        uname = platform.uname()
    except Exception:
        uname = None
    try:
        vm = psutil.virtual_memory()
    except Exception:
        vm = None
    try:
        du = psutil.disk_usage("/")
    except Exception:
        du = None
    try:
        freq = psutil.cpu_freq()
    except Exception:
        freq = None
    try:
        physical_cores = psutil.cpu_count(logical=False)
    except Exception:
        physical_cores = None
    try:
        total_cores = psutil.cpu_count(logical=True)
    except Exception:
        total_cores = None
    return jsonify(
        system=getattr(uname, "system", None),
        node=getattr(uname, "node", None),
        release=getattr(uname, "release", None),
        version=getattr(uname, "version", None),
        machine=getattr(uname, "machine", None),
        processor=getattr(uname, "processor", None),
        physical_cores=physical_cores,
        total_cores=total_cores,
        max_freq=f"{freq.max:.2f}Mhz" if freq else None,
        total_memory=humanize_bytes(vm.total) if vm else None,
        total_disk=humanize_bytes(du.total) if du else None,
    )

from werkzeug.serving import make_server

if __name__ == "__main__":
    acme_manager._auto_init()
    cert_file = acme_manager.CERT_FILE
    key_file = acme_manager.KEY_FILE

    ssl_ctx = None
    if cert_file.exists() and key_file.exists():
        try:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.verify_mode = ssl.CERT_NONE
            ssl_ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            logger.info("Loaded SSL certificate chain from: %s", cert_file)
        except Exception as e:
            logger.warning("Failed to load SSL cert chain: %s", e)
            ssl_ctx = None

    if ssl_ctx:
        logger.info("Starting HTTPS Werkzeug Server on 0.0.0.0:8080 (SSL Enabled)")
        try:
            server = make_server("0.0.0.0", 8080, app, threaded=True, ssl_context=ssl_ctx)
            server.serve_forever()
        except Exception as e:
            logger.warning("Failed to start HTTPS server, falling back to HTTP: %s", e)
            app.run(host="0.0.0.0", port=8080, threaded=True)
    else:
        logger.info("No SSL Certificate found yet. Starting HTTP server on 0.0.0.0:8080...")
        app.run(host="0.0.0.0", port=8080, threaded=True)



