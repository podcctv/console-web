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
<html lang="zh-CN" data-theme="matrix">
<head>
    <meta charset="UTF-8">
    <title>{{ hostname }} - Cyber Status Console</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #080c0a;
            --card-bg: rgba(12, 22, 16, 0.75);
            --card-border: #00ff6644;
            --card-border-glow: rgba(0, 255, 102, 0.25);
            --text-primary: #00ff66;
            --text-muted: #66cc99;
            --text-white: #e0ffe0;
            --accent-green: #00ff66;
            --accent-yellow: #ffcc00;
            --accent-red: #ff3366;
            --accent-blue: #00ccff;
            --terminal-bg: #050a07;
            --input-bg: #0d1a12;
            --bar-bg: #11261a;
            --font-mono: 'JetBrains Mono', 'Consolas', monospace;
            --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
        }

        [data-theme="cyberpunk"] {
            --bg-color: #0b0714;
            --card-bg: rgba(22, 12, 34, 0.75);
            --card-border: #ff007755;
            --card-border-glow: rgba(255, 0, 119, 0.3);
            --text-primary: #ff0077;
            --text-muted: #b566ff;
            --text-white: #ffe0fa;
            --accent-green: #00ffcc;
            --accent-yellow: #ffdd00;
            --accent-red: #ff0055;
            --accent-blue: #00aaff;
            --terminal-bg: #090412;
            --input-bg: #1a0a2a;
            --bar-bg: #261138;
        }

        [data-theme="neon"] {
            --bg-color: #060e18;
            --card-bg: rgba(10, 24, 42, 0.75);
            --card-border: #00d9ff44;
            --card-border-glow: rgba(0, 217, 255, 0.25);
            --text-primary: #00d9ff;
            --text-muted: #66b5ff;
            --text-white: #e0f4ff;
            --accent-green: #00ffaa;
            --accent-yellow: #ffaa00;
            --accent-red: #ff4466;
            --accent-blue: #0088ff;
            --terminal-bg: #040912;
            --input-bg: #0e1e33;
            --bar-bg: #122842;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body { min-height: 100%; background: var(--bg-color); color: var(--text-primary); font-family: var(--font-mono); }
        
        body {
            display: flex; flex-direction: column; align-items: center; padding: 16px;
            background-image: 
                radial-gradient(circle at 50% 0%, var(--card-border-glow), transparent 70%),
                linear-gradient(to bottom, rgba(255,255,255,0.02) 1px, transparent 1px);
            background-size: 100% 100%, 100% 24px;
        }

        .container {
            width: 100%; max-width: 1200px; display: flex; flex-direction: column; gap: 20px;
        }

        /* Top Header Bar */
        .header-bar {
            display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
            background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px;
            padding: 16px 24px; backdrop-filter: blur(12px); box-shadow: 0 8px 32px rgba(0,0,0,0.5);
        }

        .brand-title {
            display: flex; align-items: center; gap: 12px; font-size: 1.25rem; font-weight: 700; color: var(--text-white);
            letter-spacing: 0.5px;
        }

        .brand-icon {
            display: inline-flex; align-items: center; justify-content: center;
            width: 36px; height: 36px; border-radius: 8px; background: rgba(0,255,102,0.1);
            border: 1px solid var(--text-primary); color: var(--text-primary); font-weight: 900;
        }

        .status-badge {
            display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 20px;
            font-size: 0.8rem; font-weight: 600; background: rgba(0, 255, 102, 0.15); border: 1px solid var(--accent-green);
            color: var(--accent-green);
        }

        .pulse-dot {
            width: 8px; height: 8px; border-radius: 50%; background: var(--accent-green);
            box-shadow: 0 0 10px var(--accent-green); animation: pulse 1.5s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); opacity: 0.8; }
            50% { transform: scale(1.3); opacity: 1; }
            100% { transform: scale(0.95); opacity: 0.8; }
        }

        .controls-group {
            display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
        }

        .btn-toggle, .select-input {
            background: var(--input-bg); border: 1px solid var(--card-border); color: var(--text-white);
            padding: 6px 14px; border-radius: 8px; font-family: var(--font-mono); font-size: 0.85rem;
            cursor: pointer; transition: all 0.2s ease; display: inline-flex; align-items: center; gap: 6px;
        }

        .btn-toggle:hover, .select-input:hover {
            border-color: var(--text-primary); box-shadow: 0 0 12px var(--card-border-glow);
        }

        /* Banner Art */
        .ascii-banner {
            background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px;
            padding: 16px 20px; font-size: 0.72rem; line-height: 1.15; overflow-x: auto; color: var(--text-primary);
            box-shadow: 0 4px 20px rgba(0,0,0,0.3); text-shadow: 0 0 5px var(--card-border-glow);
        }

        /* Grid Layout */
        .dashboard-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px;
        }

        .card {
            background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px;
            padding: 20px; backdrop-filter: blur(10px); box-shadow: 0 8px 32px rgba(0,0,0,0.4);
            display: flex; flex-direction: column; gap: 16px; transition: transform 0.2s ease, border-color 0.2s ease;
        }

        .card:hover {
            border-color: var(--text-primary); box-shadow: 0 8px 32px var(--card-border-glow);
        }

        .card-header {
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px dashed var(--card-border); padding-bottom: 10px; font-weight: 700;
            font-size: 1rem; color: var(--text-white);
        }

        .card-header-icon { color: var(--text-primary); margin-right: 8px; }

        /* Metric Rows & Progress Bars */
        .metric-row {
            display: flex; flex-direction: column; gap: 6px;
        }

        .metric-label-val {
            display: flex; justify-content: space-between; font-size: 0.85rem;
        }

        .metric-name { color: var(--text-muted); }
        .metric-val { color: var(--text-white); font-weight: 600; }

        .progress-track {
            height: 10px; background: var(--bar-bg); border-radius: 6px; overflow: hidden;
            border: 1px solid rgba(255,255,255,0.05); position: relative;
        }

        .progress-fill {
            height: 100%; width: 0%; background: linear-gradient(90deg, var(--text-primary), var(--accent-green));
            border-radius: 6px; transition: width 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 0 10px var(--text-primary);
        }

        .progress-fill.warn { background: linear-gradient(90deg, var(--accent-yellow), #ffaa00); box-shadow: 0 0 10px var(--accent-yellow); }
        .progress-fill.danger { background: linear-gradient(90deg, var(--accent-red), #ff0033); box-shadow: 0 0 10px var(--accent-red); }

        /* Info List */
        .info-grid {
            display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.82rem;
        }

        .info-item {
            display: flex; flex-direction: column; gap: 2px; background: var(--input-bg);
            padding: 8px 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.03);
        }

        .info-item.full-width { grid-column: span 2; }
        .info-key { color: var(--text-muted); font-size: 0.75rem; }
        .info-value { color: var(--text-white); font-weight: 600; word-break: break-all; }

        /* Latency Ping Monitor with Digital LED Dot Matrix */
        .ping-grid {
            display: flex; flex-direction: column; gap: 14px;
        }

        .ping-item {
            display: flex; flex-direction: column; gap: 8px; background: var(--input-bg);
            padding: 12px 14px; border-radius: 8px; border: 1px solid var(--card-border);
        }

        .ping-header {
            display: flex; justify-content: space-between; align-items: center; font-size: 0.85rem;
        }

        .ping-title { color: var(--text-white); font-weight: 600; display: flex; align-items: center; gap: 6px; }
        .ping-value-group { display: flex; align-items: center; gap: 8px; }
        .ping-value { font-weight: 700; }
        .ping-trend-badge {
            font-size: 0.72rem; padding: 1px 6px; border-radius: 4px; font-weight: 600; font-family: var(--font-mono);
            background: rgba(255,255,255,0.05); color: var(--text-muted); border: 1px solid rgba(255,255,255,0.05);
        }
        .ping-trend-badge.trend-down { color: var(--accent-green); background: rgba(0,255,102,0.1); border-color: rgba(0,255,102,0.2); }
        .ping-trend-badge.trend-up { color: var(--accent-red); background: rgba(255,51,102,0.1); border-color: rgba(255,51,102,0.2); }

        /* Pixel Art Latency Bar Chart */
        .pixel-bar-container {
            display: flex; align-items: flex-end; gap: 2px; height: 44px; margin-top: 4px;
            padding: 4px 6px; background: rgba(0,0,0,0.5); border-radius: 6px;
            border: 1px solid var(--card-border); overflow: hidden; position: relative;
        }

        .pixel-bar-container::before {
            content: ''; position: absolute; left: 6px; right: 6px; bottom: 26px;
            border-top: 1px dashed rgba(255,255,255,0.06);
        }

        .pixel-bar-container::after {
            content: ''; position: absolute; left: 6px; right: 6px; bottom: 14px;
            border-top: 1px dashed rgba(255,255,255,0.04);
        }

        .pixel-bar {
            flex: 1; min-width: 4px; max-width: 8px; border-radius: 1px 1px 0 0;
            transition: height 0.2s ease, background 0.2s ease, box-shadow 0.2s ease;
            image-rendering: pixelated;
        }

        .pixel-bar.px-green {
            background: var(--accent-green);
            box-shadow: 0 0 4px var(--accent-green), 0 -2px 6px rgba(0,255,102,0.3);
        }

        .pixel-bar.px-yellow {
            background: var(--accent-yellow);
            box-shadow: 0 0 4px var(--accent-yellow), 0 -2px 6px rgba(255,204,0,0.3);
        }

        .pixel-bar.px-red {
            background: var(--accent-red);
            box-shadow: 0 0 4px var(--accent-red), 0 -2px 6px rgba(255,51,102,0.3);
        }

        .pixel-bar.px-timeout {
            background: #ff0033; min-height: 3px;
            box-shadow: 0 0 4px #ff0033;
        }

        .pixel-bar.px-empty {
            background: rgba(255,255,255,0.04); min-height: 2px;
        }

        .timeline-ticks {
            display: flex; justify-content: space-between; font-size: 0.68rem; color: var(--text-muted);
            margin-top: 2px; padding: 0 4px; font-family: var(--font-mono); opacity: 0.7;
        }

        .ping-legend {
            display: flex; gap: 12px; justify-content: flex-end; font-size: 0.75rem; margin-top: 4px;
        }

        /* Quick Lookup Card */
        .lookup-form {
            display: flex; gap: 8px; margin-top: 4px;
        }

        .lookup-input {
            flex: 1; background: var(--input-bg); border: 1px solid var(--card-border);
            color: var(--text-white); padding: 8px 12px; border-radius: 8px; font-family: var(--font-mono);
            font-size: 0.85rem; outline: none;
        }

        .lookup-input:focus { border-color: var(--text-primary); box-shadow: 0 0 10px var(--card-border-glow); }

        .lookup-btn {
            background: var(--text-primary); color: #000; border: none; padding: 8px 16px;
            border-radius: 8px; font-weight: 700; font-family: var(--font-mono); cursor: pointer;
            transition: all 0.2s ease;
        }

        .lookup-btn:hover { opacity: 0.9; transform: translateY(-1px); }

        .lookup-result {
            display: none; flex-direction: column; gap: 8px; background: var(--input-bg);
            padding: 12px; border-radius: 8px; border: 1px dashed var(--text-primary); font-size: 0.85rem;
        }

        /* Terminal Window */
        .terminal-card {
            background: var(--terminal-bg); border: 1px solid var(--card-border); border-radius: 12px;
            padding: 0; overflow: hidden; box-shadow: 0 12px 40px rgba(0,0,0,0.6);
            display: flex; flex-direction: column; height: 380px;
        }

        .terminal-header {
            background: rgba(255,255,255,0.03); border-bottom: 1px solid var(--card-border);
            padding: 10px 16px; display: flex; justify-content: space-between; align-items: center;
        }

        .terminal-buttons { display: flex; gap: 8px; }
        .win-dot { width: 12px; height: 12px; border-radius: 50%; }
        .win-red { background: #ff5f56; }
        .win-yellow { background: #ffbd2e; }
        .win-green { background: #27c93f; }

        .terminal-quick-actions {
            display: flex; gap: 8px; flex-wrap: wrap;
        }

        .action-chip {
            background: rgba(255,255,255,0.05); border: 1px solid var(--card-border); color: var(--text-muted);
            padding: 3px 8px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; transition: all 0.15s ease;
        }

        .action-chip:hover { color: var(--text-white); border-color: var(--text-primary); background: rgba(0,255,102,0.1); }

        .terminal-body {
            flex: 1; padding: 14px 16px; overflow-y: auto; font-size: 0.88rem; line-height: 1.5;
            display: flex; flex-direction: column; gap: 8px; word-break: break-word;
        }

        #cmd_output {
            white-space: pre-wrap; font-family: var(--font-mono); color: var(--text-white);
        }

        .terminal-input-line {
            display: flex; align-items: center; gap: 8px; margin-top: 4px;
        }

        .prompt-text { color: var(--text-primary); font-weight: 700; white-space: nowrap; }

        .terminal-input {
            flex: 1; background: transparent; border: none; outline: none; color: var(--text-white);
            font-family: var(--font-mono); font-size: 0.88rem; caret-color: var(--text-primary);
        }

        /* IP Quality Check Card - Compact Edition */
        .ipcheck-card {
            background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px;
            padding: 14px 18px; backdrop-filter: blur(10px); box-shadow: 0 8px 32px rgba(0,0,0,0.4);
            display: flex; flex-direction: column; gap: 10px; transition: transform 0.2s ease, border-color 0.2s ease;
        }
        .ipcheck-card:hover { border-color: var(--text-primary); box-shadow: 0 8px 32px var(--card-border-glow); }

        .ipcheck-header {
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px dashed var(--card-border); padding-bottom: 8px;
        }
        .ipcheck-header-left { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 0.95rem; color: var(--text-white); }
        .ipcheck-btn {
            background: var(--text-primary); color: #000; border: none; padding: 4px 12px;
            border-radius: 6px; font-weight: 700; font-family: var(--font-mono); font-size: 0.78rem;
            cursor: pointer; transition: all 0.2s ease; display: inline-flex; align-items: center; gap: 6px;
        }
        .ipcheck-btn:hover { opacity: 0.85; transform: translateY(-1px); }
        .ipcheck-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .ipcheck-btn .spinner {
            width: 12px; height: 12px; border: 2px solid rgba(0,0,0,0.3); border-top-color: #000;
            border-radius: 50%; animation: spin 0.6s linear infinite; display: none;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        .ipcheck-body { display: flex; flex-direction: column; gap: 10px; }

        /* Compact Three-column info row */
        .ipcheck-info-row {
            display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px;
        }
        .ipcheck-section {
            background: var(--input-bg); border: 1px solid var(--card-border); border-radius: 8px;
            padding: 8px 12px; display: flex; flex-direction: column; gap: 4px;
        }
        .ipcheck-section-title {
            font-size: 0.78rem; font-weight: 700; color: var(--text-primary);
            border-bottom: 1px dashed rgba(255,255,255,0.08); padding-bottom: 4px; margin-bottom: 2px;
            display: flex; align-items: center; gap: 6px;
        }
        .ipcheck-row {
            display: flex; justify-content: space-between; align-items: center;
            font-size: 0.75rem; padding: 1px 0;
        }
        .ipcheck-label { color: var(--text-muted); }
        .ipcheck-val { color: var(--text-white); font-weight: 600; text-align: right; max-width: 65%; word-break: break-all; }

        /* Compact Risk score bar */
        .risk-bar-track {
            height: 6px; background: var(--bar-bg); border-radius: 4px; overflow: hidden;
            border: 1px solid rgba(255,255,255,0.05); position: relative; margin-top: 2px;
        }
        .risk-bar-fill {
            height: 100%; width: 0%; border-radius: 4px; transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .risk-bar-fill.risk-vlow { background: linear-gradient(90deg, #00ff66, #00cc55); box-shadow: 0 0 8px rgba(0,255,102,0.5); }
        .risk-bar-fill.risk-low { background: linear-gradient(90deg, #00ff66, #66ff99); box-shadow: 0 0 8px rgba(0,255,102,0.4); }
        .risk-bar-fill.risk-med { background: linear-gradient(90deg, #ffcc00, #ffaa00); box-shadow: 0 0 8px rgba(255,204,0,0.5); }
        .risk-bar-fill.risk-high { background: linear-gradient(90deg, #ff6633, #ff3366); box-shadow: 0 0 8px rgba(255,51,102,0.5); }
        .risk-bar-fill.risk-vhigh { background: linear-gradient(90deg, #ff0033, #cc0022); box-shadow: 0 0 8px rgba(255,0,51,0.6); }

        /* IP Type Badge */
        .ip-type-badge {
            display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px;
            font-size: 0.72rem; font-weight: 700; letter-spacing: 0.3px;
        }
        .ip-type-isp { background: rgba(0,255,102,0.15); color: var(--accent-green); border: 1px solid var(--accent-green); }
        .ip-type-hosting { background: rgba(255,51,102,0.15); color: var(--accent-red); border: 1px solid var(--accent-red); }
        .ip-type-business { background: rgba(255,204,0,0.15); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
        .ip-type-mobile { background: rgba(0,204,255,0.15); color: var(--accent-blue); border: 1px solid var(--accent-blue); }
        .ip-type-proxy { background: rgba(255,51,102,0.15); color: var(--accent-red); border: 1px solid var(--accent-red); }
        .ip-type-vpn { background: rgba(255,204,0,0.15); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
        .ip-type-tor { background: rgba(255,0,51,0.2); color: #ff4466; border: 1px solid #ff4466; }

        /* Risk factor badges */
        .factor-yes { color: var(--accent-red); font-weight: 700; }
        .factor-no { color: var(--accent-green); font-weight: 700; }

        /* Compact Media/AI unlock grid (chips layout) */
        .unlock-section-title {
            font-size: 0.78rem; font-weight: 700; color: var(--text-primary);
            border-bottom: 1px dashed rgba(255,255,255,0.08); padding-bottom: 4px;
            display: flex; align-items: center; gap: 6px; margin-top: 2px;
        }
        .unlock-grid {
            display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-top: 4px;
        }
        .unlock-tile {
            background: var(--input-bg); border: 1px solid var(--card-border); border-radius: 6px;
            padding: 6px 10px; display: flex; align-items: center; justify-content: space-between; gap: 6px;
            transition: all 0.2s ease; font-size: 0.74rem;
        }
        .unlock-tile:hover { border-color: var(--text-primary); box-shadow: 0 0 8px var(--card-border-glow); }
        .unlock-tile-left { display: flex; align-items: center; gap: 6px; font-weight: 600; color: var(--text-white); }
        .unlock-tile-icon { font-size: 1rem; }
        .unlock-tile-name { color: var(--text-white); font-weight: 600; white-space: nowrap; }
        .unlock-tile-status {
            display: inline-flex; align-items: center; gap: 3px; padding: 1px 6px; border-radius: 8px;
            font-size: 0.68rem; font-weight: 700; white-space: nowrap;
        }
        .unlock-yes { background: rgba(0,255,102,0.15); color: var(--accent-green); border: 1px solid rgba(0,255,102,0.3); }
        .unlock-no { background: rgba(255,51,102,0.15); color: var(--accent-red); border: 1px solid rgba(255,51,102,0.3); }
        .unlock-fail { background: rgba(255,204,0,0.1); color: var(--accent-yellow); border: 1px solid rgba(255,204,0,0.2); }

        /* Skeleton loading */
        .skeleton-line {
            height: 12px; background: linear-gradient(90deg, rgba(255,255,255,0.03) 25%, rgba(255,255,255,0.08) 50%, rgba(255,255,255,0.03) 75%);
            background-size: 200% 100%; animation: shimmer 1.5s infinite; border-radius: 4px; margin: 4px 0;
        }
        @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

        /* Scrollbars */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg-color); }
        ::-webkit-scrollbar-thumb { background: var(--card-border); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-primary); }

        @media (max-width: 768px) {
            body { padding: 10px; }
            .header-bar { padding: 12px 16px; }
            .dashboard-grid { grid-template-columns: 1fr; }
            .info-grid { grid-template-columns: 1fr; }
            .info-item.full-width { grid-column: span 1; }
            .ascii-banner { font-size: 0.55rem; }
            .ipcheck-info-row { grid-template-columns: 1fr; }
            .unlock-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header Bar -->
        <header class="header-bar">
            <div class="brand-title">
                <span class="brand-icon">&gt;_</span>
                <span>{{ hostname }}</span>
                <span class="status-badge"><span class="pulse-dot"></span> ONLINE</span>
                <span id="acme_badge" class="status-badge" style="background:rgba(0,204,255,0.1); border-color:var(--accent-blue); color:var(--accent-blue);">🔒 SSL 智能检测中...</span>
            </div>
            <div class="controls-group">
                <select id="theme_select" class="select-input">
                    <option value="matrix">🟢 Matrix Classic</option>
                    <option value="cyberpunk">🟣 Cyberpunk Neon</option>
                    <option value="neon">🔵 Tech Blue</option>
                </select>
                <select id="interval_select" class="select-input">
                    <option value="1000">⚡ 1s 刷新</option>
                    <option value="2000">⏱️ 2s 刷新</option>
                    <option value="5000">🐢 5s 刷新</option>
                    <option value="0">⏸️ 暂停刷新</option>
                </select>
            </div>
        </header>

        <!-- ASCII Banner Header -->
        <pre class="ascii-banner">
    _   ______  ____  ______   _____ ______________ __ __________
   / | / / __ \/ __ \/ ____/  / ___// ____/ ____/ //_// ____/ __ \
  /  |/ / / / / / / / __/     \__ \/ __/ / __/ / ,&lt;  / __/ / /_/ /
 / /|  / /_/ / /_/ / /___    ___/ / /___/ /___/ /| |/ /___/ _, _/
/_/ |_|\____/_____/_/____/   /____/_____/_____/_/ |_|_/____/_/ |_|

Welcome to Console-Web Cyber Edition 🚀 | System Status &amp; Realtime Network Monitor
        </pre>

        <!-- Dashboard Cards Grid -->
        <div class="dashboard-grid">
            <!-- Card 1: System Performance -->
            <div class="card">
                <div class="card-header">
                    <span><span class="card-header-icon">⚡</span> 核心系统性能</span>
                    <span id="load_val" style="font-size:0.75rem; color:var(--text-muted)">Load: -</span>
                </div>

                <div class="metric-row">
                    <div class="metric-label-val">
                        <span class="metric-name">CPU 使用率</span>
                        <span class="metric-val" id="cpu_val">0.0%</span>
                    </div>
                    <div class="progress-track">
                        <div class="progress-fill" id="cpu_bar"></div>
                    </div>
                </div>

                <div class="metric-row">
                    <div class="metric-label-val">
                        <span class="metric-name">内存 使用率</span>
                        <span class="metric-val" id="memory_val">0.0%</span>
                    </div>
                    <div class="progress-track">
                        <div class="progress-fill" id="memory_bar"></div>
                    </div>
                </div>

                <div class="metric-row">
                    <div class="metric-label-val">
                        <span class="metric-name">磁盘 使用率</span>
                        <span class="metric-val" id="disk_val">0.0%</span>
                    </div>
                    <div class="progress-track">
                        <div class="progress-fill" id="disk_bar"></div>
                    </div>
                </div>

                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-key">容器运行时间</span>
                        <span class="info-value" id="cuptime">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-key">宿主机运行时间</span>
                        <span class="info-value" id="huptime">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-key">CPU 核心 / 逻辑</span>
                        <span class="info-value" id="cpu_cores">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-key">系统架构 / 体系</span>
                        <span class="info-value" id="arch_val">-</span>
                    </div>
                    <div class="info-item full-width">
                        <span class="info-key">磁盘 IO (累计读/写)</span>
                        <span class="info-value" id="disk_io">-</span>
                    </div>
                </div>
            </div>

            <!-- Card 2: Network & Connectivity -->
            <div class="card">
                <div class="card-header">
                    <span><span class="card-header-icon">🌐</span> 网络流量与节点</span>
                </div>

                <div class="info-grid">
                    <div class="info-item full-width">
                        <span class="info-key">网络实时速率 (上传/下载)</span>
                        <span class="info-value" id="net_io" style="color:var(--accent-green)">-</span>
                    </div>
                    <div class="info-item full-width">
                        <span class="info-key">服务器 IP (内网/公网)</span>
                        <span class="info-value" id="ip_val">-</span>
                    </div>
                    <div class="info-item full-width">
                        <span class="info-key">您的 客户端 IP &amp; 运营商</span>
                        <span class="info-value" id="client_ip_val">-</span>
                    </div>
                </div>

                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-key">ACME SSL 证书状态</span>
                        <span class="info-value" id="acme_val" style="color:var(--accent-blue)">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-key">操作系统</span>
                        <span class="info-value" id="os_val">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-key">物理/总内存</span>
                        <span class="info-value" id="mem_total_val">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-key">总磁盘容量</span>
                        <span class="info-value" id="disk_total_val">-</span>
                    </div>
                </div>
            </div>

            <!-- Card 3: Ping & Latency Dashboard (Pure Digital Dot Matrix Bar) -->
            <div class="card">
                <div class="card-header">
                    <span><span class="card-header-icon">📡</span> 网络延迟 (TCP Ping)</span>
                    <div class="ping-legend">
                        <span style="color:var(--accent-green)">● &lt;80ms</span>
                        <span style="color:var(--accent-yellow)">● &lt;160ms</span>
                        <span style="color:var(--accent-red)">● &ge;160ms</span>
                    </div>
                </div>

                <div class="ping-grid">
                    <div class="ping-item" id="client_ping_item">
                        <div class="ping-header">
                            <span class="ping-title">📍 本地/Client 延迟</span>
                            <div class="ping-value-group">
                                <span class="ping-trend-badge" id="client_ping_trend">~ 稳定</span>
                                <span class="ping-value" id="client_ping_val">-</span>
                            </div>
                        </div>
                        <div class="pixel-bar-container" id="client_ping_bars"></div>
                        <div class="timeline-ticks"><span>-40s ⏳</span><span>-20s</span><span>现在 📍</span></div>
                    </div>

                    <div class="ping-item">
                        <div class="ping-header">
                            <span class="ping-title">🟢 浙江联通 Ping</span>
                            <div class="ping-value-group">
                                <span class="ping-trend-badge" id="ping_cu_trend">~ 稳定</span>
                                <span class="ping-value" id="ping_cu_val">-</span>
                            </div>
                        </div>
                        <div class="pixel-bar-container" id="ping_cu_bars"></div>
                        <div class="timeline-ticks"><span>-40s ⏳</span><span>-20s</span><span>现在 📍</span></div>
                    </div>

                    <div class="ping-item">
                        <div class="ping-header">
                            <span class="ping-title">🔵 浙江移动 Ping</span>
                            <div class="ping-value-group">
                                <span class="ping-trend-badge" id="ping_cm_trend">~ 稳定</span>
                                <span class="ping-value" id="ping_cm_val">-</span>
                            </div>
                        </div>
                        <div class="pixel-bar-container" id="ping_cm_bars"></div>
                        <div class="timeline-ticks"><span>-40s ⏳</span><span>-20s</span><span>现在 📍</span></div>
                    </div>

                    <div class="ping-item">
                        <div class="ping-header">
                            <span class="ping-title">🟡 浙江电信 Ping</span>
                            <div class="ping-value-group">
                                <span class="ping-trend-badge" id="ping_ct_trend">~ 稳定</span>
                                <span class="ping-value" id="ping_ct_val">-</span>
                            </div>
                        </div>
                        <div class="pixel-bar-container" id="ping_ct_bars"></div>
                        <div class="timeline-ticks"><span>-40s ⏳</span><span>-20s</span><span>现在 📍</span></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Card 4: IP Quality Check & Streaming/AI Unlock Detection -->
        <div class="ipcheck-card" id="ipcheck_card">
            <div class="ipcheck-header">
                <div class="ipcheck-header-left">
                    <span class="card-header-icon">📊</span>
                    <span>IP 质量体检 & 解锁检测</span>
                </div>
                <button class="ipcheck-btn" id="ipcheck_btn" onclick="fetchIPCheck()">
                    <span class="spinner" id="ipcheck_spinner"></span>
                    <span id="ipcheck_btn_text">开始检测</span>
                </button>
            </div>

            <div class="ipcheck-body" id="ipcheck_body">
                <!-- Three columns: Basic Info / IP Type / Risk Score -->
                <div class="ipcheck-info-row">
                    <!-- Basic Info -->
                    <div class="ipcheck-section">
                        <div class="ipcheck-section-title">🌍 基础信息</div>
                        <div class="ipcheck-row"><span class="ipcheck-label">IP 地址</span><span class="ipcheck-val" id="ipc_ip">-</span></div>
                        <div class="ipcheck-row"><span class="ipcheck-label">ASN</span><span class="ipcheck-val" id="ipc_asn">-</span></div>
                        <div class="ipcheck-row"><span class="ipcheck-label">组织</span><span class="ipcheck-val" id="ipc_org">-</span></div>
                        <div class="ipcheck-row"><span class="ipcheck-label">ISP</span><span class="ipcheck-val" id="ipc_isp">-</span></div>
                        <div class="ipcheck-row"><span class="ipcheck-label">国家</span><span class="ipcheck-val" id="ipc_country">-</span></div>
                        <div class="ipcheck-row"><span class="ipcheck-label">城市</span><span class="ipcheck-val" id="ipc_city">-</span></div>
                        <div class="ipcheck-row"><span class="ipcheck-label">时区</span><span class="ipcheck-val" id="ipc_tz">-</span></div>
                    </div>

                    <!-- IP Type -->
                    <div class="ipcheck-section">
                        <div class="ipcheck-section-title">🏷️ IP 类型属性</div>
                        <div class="ipcheck-row"><span class="ipcheck-label">IP 类型</span><span class="ipcheck-val" id="ipc_type">-</span></div>
                        <div class="ipcheck-row"><span class="ipcheck-label">代理 Proxy</span><span class="ipcheck-val" id="ipc_proxy">-</span></div>
                        <div class="ipcheck-row"><span class="ipcheck-label">VPN</span><span class="ipcheck-val" id="ipc_vpn">-</span></div>
                        <div class="ipcheck-row"><span class="ipcheck-label">Tor</span><span class="ipcheck-val" id="ipc_tor">-</span></div>
                        <div class="ipcheck-row"><span class="ipcheck-label">机房 Hosting</span><span class="ipcheck-val" id="ipc_hosting">-</span></div>
                        <div class="ipcheck-row"><span class="ipcheck-label">手机网络</span><span class="ipcheck-val" id="ipc_mobile">-</span></div>
                    </div>

                    <!-- Risk Score -->
                    <div class="ipcheck-section">
                        <div class="ipcheck-section-title">⚠️ 风险评分</div>
                        <div class="ipcheck-row">
                            <span class="ipcheck-label">风险评分</span>
                            <span class="ipcheck-val" id="ipc_risk_score" style="font-size:1.1rem">-</span>
                        </div>
                        <div class="risk-bar-track">
                            <div class="risk-bar-fill" id="ipc_risk_bar"></div>
                        </div>
                        <div class="ipcheck-row">
                            <span class="ipcheck-label">风险等级</span>
                            <span class="ipcheck-val" id="ipc_risk_label">-</span>
                        </div>
                        <div style="margin-top:6px; font-size:0.68rem; color:var(--text-muted); text-align:center;">
                            <span style="color:var(--accent-green)">■ 极低</span>&nbsp;
                            <span style="color:var(--accent-green)">■ 低</span>&nbsp;
                            <span style="color:var(--accent-yellow)">■ 中等</span>&nbsp;
                            <span style="color:var(--accent-red)">■ 高</span>&nbsp;
                            <span style="color:#ff0033">■ 极高</span>
                        </div>
                        <div class="ipcheck-row" style="margin-top:4px">
                            <span class="ipcheck-label">检测时间</span>
                            <span class="ipcheck-val" id="ipc_time" style="font-size:0.7rem">-</span>
                        </div>
                    </div>
                </div>

                <!-- Media & AI Unlock Detection -->
                <div class="unlock-section-title">🎬 流媒体 & AI 服务解锁检测</div>
                <div class="unlock-grid" id="unlock_grid">
                    <!-- Tiles populated by JS -->
                </div>
            </div>
        </div>

        <!-- Quick Lookup Tool Widget -->
        <div class="card">
            <div class="card-header">
                <span><span class="card-header-icon">🔍</span> 快速域名/IP 诊断工具</span>
            </div>
            <div class="lookup-form">
                <input type="text" id="lookup_input" class="lookup-input" placeholder="输入域名或 IP (例如: github.com 或 8.8.8.8)" />
                <button id="lookup_btn" class="lookup-btn">开始查询</button>
            </div>
            <div id="lookup_result" class="lookup-result">
                <div><strong>目标:</strong> <span id="res_target">-</span></div>
                <div><strong>解析 IP:</strong> <span id="res_ip" style="color:var(--accent-green)">-</span></div>
                <div><strong>运营商 / 位置:</strong> <span id="res_isp">-</span></div>
                <div><strong>TCP 响应延迟:</strong> <span id="res_ping" style="color:var(--text-white)">-</span></div>
            </div>
        </div>

        <!-- Terminal Console Section -->
        <div class="terminal-card" id="terminal_box">
            <div class="terminal-header">
                <div class="terminal-buttons">
                    <div class="win-dot win-red"></div>
                    <div class="win-dot win-yellow"></div>
                    <div class="win-dot win-green"></div>
                </div>
                <div class="terminal-quick-actions">
                    <span class="action-chip" onclick="quickRun('ipcheck')">IP 质量体检</span>
                    <span class="action-chip" onclick="quickRun('acme status')">ACME 证书状态</span>
                    <span class="action-chip" onclick="quickRun('acme issue')">申请 IP 证书</span>
                    <span class="action-chip" onclick="quickRun('ping zj-cu-v4.ip.zstaticcdn.com')">Ping 联通</span>
                    <span class="action-chip" onclick="quickRun('ping zj-cm-v4.ip.zstaticcdn.com')">Ping 移动</span>
                    <span class="action-chip" onclick="quickRun('ping zj-ct-v4.ip.zstaticcdn.com')">Ping 电信</span>
                    <span class="action-chip" onclick="quickRun('mtr 1.1.1.1')">MTR 1.1.1.1</span>
                    <span class="action-chip" onclick="quickRun('clear')">清屏</span>
                    <span class="action-chip" onclick="quickRun('help')">帮助</span>
                </div>
            </div>
            <div class="terminal-body" id="terminal_body">
                <pre id="cmd_output">System initialized. Type 'help' for available commands.
Try typing 'acme status' or 'acme issue' or 'ping 8.8.8.8'
</pre>
                <div class="terminal-input-line">
                    <span class="prompt-text">root@{{ short_isp }}:~$</span>
                    <input type="text" id="cmd_input" class="terminal-input" placeholder="输入命令..." autofocus autocomplete="off" />
                </div>
            </div>
        </div>
    </div>

    <script>
    // Theme switcher
    const themeSelect = document.getElementById('theme_select');
    themeSelect.addEventListener('change', e => {
        document.documentElement.setAttribute('data-theme', e.target.value);
        localStorage.setItem('console_theme', e.target.value);
    });
    const savedTheme = localStorage.getItem('console_theme') || 'matrix';
    themeSelect.value = savedTheme;
    document.documentElement.setAttribute('data-theme', savedTheme);

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

    // Color helpers for metrics
    function getMetricColor(pct) {
        if (pct < 50) return 'var(--text-primary)';
        if (pct < 80) return 'var(--accent-yellow)';
        return 'var(--accent-red)';
    }

    function updateProgress(id, pct) {
        const valEl = document.getElementById(id + '_val');
        const barEl = document.getElementById(id + '_bar');
        if (valEl) valEl.textContent = `${pct.toFixed(1)}%`;
        if (barEl) {
            barEl.style.width = `${Math.min(100, Math.max(0, pct))}%`;
            barEl.className = 'progress-fill';
            if (pct >= 80) barEl.classList.add('danger');
            else if (pct >= 50) barEl.classList.add('warn');
        }
    }

    // Safe DOM Text Setter
    function setElText(id, text) {
        const el = document.getElementById(id);
        if (el) el.textContent = (text !== null && text !== undefined) ? text : '-';
    }

    // Fetch ACME SSL Status
    async function fetchAcmeStatus() {
        try {
            const res = await fetch('/acme/status');
            const data = await res.json();
            const badge = document.getElementById('acme_badge');
            const valEl = document.getElementById('acme_val');
            if (data.has_cert) {
                if (badge) {
                    badge.style.borderColor = 'var(--accent-green)';
                    badge.style.color = 'var(--accent-green)';
                    badge.textContent = `🔒 SSL 已开启 (${data.days_left}天)`;
                }
                setElText('acme_val', `${data.domain} (${data.days_left}天后到期)`);
            } else {
                if (badge) {
                    badge.style.borderColor = 'var(--text-muted)';
                    badge.style.color = 'var(--text-muted)';
                    badge.textContent = `🔓 HTTP 运行中`;
                }
                setElText('acme_val', `未安装 (可运行 'acme issue' 自动申请)`);
            }
        } catch(e) {}
    }

    // Fetch stats
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
            setElText('ip_val', data.ip);

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
            setElText('os_val', data.system ? `${data.system} ${data.release || ''}` : '-');
            setElText('arch_val', data.machine);
            setElText('mem_total_val', data.total_memory);
            setElText('disk_total_val', data.total_disk);
        } catch(e) {}
    }

    // Ping history & Overall Trend Calculation
    const pingHistory = { client_ping: [], ping_cu: [], ping_cm: [], ping_ct: [] };
    const MAX_BARS = 40;
    const MAX_HEIGHT = 40; // px
    const MAX_MS = 300;

    function getPingColor(ms) {
        if (ms === null || ms === undefined) return 'var(--accent-red)';
        if (ms < 80) return 'var(--accent-green)';
        if (ms < 160) return 'var(--accent-yellow)';
        return 'var(--accent-red)';
    }

    function renderPixelBars(key) {
        const container = document.getElementById(key + '_bars');
        if (!container) return;
        const rawHistory = pingHistory[key];
        if (!rawHistory.length) return;

        // Apply Exponential Moving Average (EMA) smoothing for clean overall trend visualization
        const history = [];
        let ema = null;
        const alpha = 0.35;
        for (let i = 0; i < rawHistory.length; i++) {
            const val = rawHistory[i];
            if (val === null || val === undefined) {
                history.push(null);
            } else {
                if (ema === null) ema = val;
                else ema = alpha * val + (1 - alpha) * ema;
                history.push(ema);
            }
        }

        while (container.children.length < MAX_BARS) {
            const bar = document.createElement('div');
            bar.className = 'pixel-bar px-empty';
            bar.style.height = '2px';
            container.appendChild(bar);
        }
        while (container.children.length > MAX_BARS) {
            container.removeChild(container.lastChild);
        }

        const bars = container.children;
        const offset = MAX_BARS - history.length;

        for (let i = 0; i < MAX_BARS; i++) {
            const bar = bars[i];
            const dataIdx = i - offset;

            if (dataIdx < 0 || dataIdx >= history.length) {
                bar.className = 'pixel-bar px-empty';
                bar.style.height = '2px';
                continue;
            }

            const ms = history[dataIdx];
            if (ms === null || ms === undefined) {
                bar.className = 'pixel-bar px-timeout';
                bar.style.height = '3px';
            } else {
                const h = Math.max(3, Math.round((Math.min(ms, MAX_MS) / MAX_MS) * MAX_HEIGHT));
                bar.style.height = h + 'px';
                if (ms < 80) bar.className = 'pixel-bar px-green';
                else if (ms < 160) bar.className = 'pixel-bar px-yellow';
                else bar.className = 'pixel-bar px-red';
            }
        }
    }

    function updatePingUI(key, ms) {
        const valEl = document.getElementById(key + '_val');
        const trendEl = document.getElementById(key + '_trend');

        pingHistory[key].push(ms);
        if (pingHistory[key].length > MAX_BARS) pingHistory[key].shift();

        const history = pingHistory[key];
        const validSamples = history.filter(v => v !== null && v !== undefined);

        // Overall trend calculation: compare recent window average vs initial baseline average
        if (valEl) {
            if (ms === null || ms === undefined) {
                valEl.textContent = '超时/不可达';
                valEl.style.color = 'var(--accent-red)';
            } else {
                const avg = validSamples.length ? (validSamples.reduce((a,b)=>a+b,0) / validSamples.length) : ms;
                valEl.innerHTML = `${ms.toFixed(1)} ms <span style="font-size:0.75rem; color:var(--text-muted); font-weight:normal">(均值 ${avg.toFixed(1)}ms)</span>`;
                valEl.style.color = getPingColor(ms);
            }
        }

        if (trendEl) {
            if (validSamples.length >= 3) {
                const firstHalf = validSamples.slice(0, Math.floor(validSamples.length / 2));
                const secondHalf = validSamples.slice(Math.floor(validSamples.length / 2));
                const avgOld = firstHalf.reduce((a,b)=>a+b,0) / firstHalf.length;
                const avgNew = secondHalf.reduce((a,b)=>a+b,0) / secondHalf.length;
                const diff = avgNew - avgOld;

                if (diff <= -2.0) {
                    trendEl.textContent = `↓ 较初始 ${diff.toFixed(1)}ms`;
                    trendEl.className = 'ping-trend-badge trend-down';
                } else if (diff >= 2.0) {
                    trendEl.textContent = `↑ 较初始 +${diff.toFixed(1)}ms`;
                    trendEl.className = 'ping-trend-badge trend-up';
                } else {
                    trendEl.textContent = '~ 整体平稳';
                    trendEl.className = 'ping-trend-badge';
                }
            } else {
                trendEl.textContent = '~ 整体平稳';
                trendEl.className = 'ping-trend-badge';
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
        } catch (e) {
            console.error("Failed to fetch pings:", e);
        }
    }

    // Quick Lookup Form
    const lookupBtn = document.getElementById('lookup_btn');
    const lookupInput = document.getElementById('lookup_input');
    const lookupResult = document.getElementById('lookup_result');

    async function doLookup(target) {
        if (!target) return;
        lookupBtn.textContent = '查询中...';
        try {
            const res = await fetch(`/pinginfo?url=${encodeURIComponent(target)}`);
            if (!res.ok) throw new Error("查询失败");
            const data = await res.json();
            document.getElementById('res_target').textContent = data.host || target;
            document.getElementById('res_ip').textContent = data.ip || '解析失败';
            document.getElementById('res_isp').textContent = data.isp || '未知 ISP';
            document.getElementById('res_ping').textContent = data.ping !== null ? `${data.ping.toFixed(1)} ms` : '超时/未知';
            lookupResult.style.display = 'flex';
        } catch (e) {
            alert('查询出错: ' + e.message);
        } finally {
            lookupBtn.textContent = '开始查询';
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

    terminalBox.addEventListener('click', () => inputEl.focus());

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
                    appendOutput(`${PROMPT} ${text}\nInitiating ACME Certificate issuance${targetHost ? ' for ' + targetHost : ' (Auto Public IP)'}... Please wait...`);
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
                appendOutput(`${PROMPT} ${text}\nRunning IP Quality Check... Please wait (this may take 10-15s)...`);
                fetch('/ipcheck').then(r=>r.json()).then(data => {
                    if (data.error) { appendOutput(`Error: ${data.error}`); return; }
                    let out = '\n╔══════════════════════════════════════╗\n';
                    out += '║   IP QUALITY CHECK REPORT            ║\n';
                    out += '╚══════════════════════════════════════╝\n';
                    const b = data.basic || {};
                    const r2 = data.risk || {};
                    out += `\n[基础信息]\n  IP:     ${b.ip || 'N/A'}\n  ASN:    ${b.asn || 'N/A'}\n  组织:   ${b.org || 'N/A'}\n  ISP:    ${b.isp || 'N/A'}\n  位置:   ${b.country || ''} ${b.city || ''}\n  时区:   ${b.timezone || 'N/A'}`;
                    out += `\n\n[IP类型]  ${r2.ip_type_label || 'N/A'}`;
                    out += `\n  Proxy: ${r2.is_proxy ? '是 ⚠️' : '否 ✅'}  VPN: ${r2.is_vpn ? '是 ⚠️' : '否 ✅'}  Tor: ${r2.is_tor ? '是 ⚠️' : '否 ✅'}  Hosting: ${r2.is_hosting ? '是' : '否'}`;
                    out += `\n\n[风险评分]  ${r2.risk_score || 0}/100  ${r2.risk_label || ''}`;
                    out += '\n\n[流媒体 & AI 解锁]';
                    (data.media || []).forEach(m => {
                        const icon = m.status === 'unlocked' ? '✅' : m.status === 'blocked' ? '❌' : '⚠️';
                        const region = m.region ? ` [${m.region}]` : '';
                        out += `\n  ${icon} ${m.name}: ${m.status === 'unlocked' ? '解锁' : m.status === 'blocked' ? '屏蔽' : '检测失败'}${region}`;
                    });
                    out += `\n\n检测时间: ${data.timestamp || 'N/A'}`;
                    appendOutput(out);
                    // Also update the card
                    renderIPCheckResult(data);
                }).catch(err => appendOutput(`IP check error: ${err.message}`));
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
                    '  theme <matrix|cyberpunk|neon> - Change UI visual theme\n' +
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
                    appendOutput(`${PROMPT} ${text}\nUsage: theme <matrix|cyberpunk|neon>`);
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

    // IP Quality Check
    const MEDIA_ICONS = {
        'Netflix': '🎬', 'YouTube Premium': '▶️', 'Disney+': '🏰', 'TikTok': '🎵',
        'ChatGPT': '🤖', 'Claude': '🧠', 'Spotify': '🎧', 'Amazon Prime': '📦'
    };

    function renderIPCheckResult(data) {
        const body = document.getElementById('ipcheck_body');
        body.classList.add('visible');

        const b = data.basic || {};
        const r = data.risk || {};

        // Basic info
        document.getElementById('ipc_ip').textContent = b.ip || 'N/A';
        document.getElementById('ipc_asn').textContent = b.asn || 'N/A';
        document.getElementById('ipc_org').textContent = b.org || 'N/A';
        document.getElementById('ipc_isp').textContent = b.isp || 'N/A';
        const flag = b.countryCode ? String.fromCodePoint(...[...b.countryCode.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) + ' ' : '';
        document.getElementById('ipc_country').textContent = flag + (b.country || 'N/A');
        document.getElementById('ipc_city').textContent = b.city || 'N/A';
        document.getElementById('ipc_tz').textContent = b.timezone || 'N/A';

        // IP type badge
        const typeClass = 'ip-type-' + (r.ip_type || 'isp');
        document.getElementById('ipc_type').innerHTML = `<span class="ip-type-badge ${typeClass}">${r.ip_type_label || 'N/A'}</span>`;

        // Risk factors
        const factorHTML = (val) => val ? '<span class="factor-yes">⚠ 是</span>' : '<span class="factor-no">✅ 否</span>';
        document.getElementById('ipc_proxy').innerHTML = factorHTML(r.is_proxy);
        document.getElementById('ipc_vpn').innerHTML = factorHTML(r.is_vpn);
        document.getElementById('ipc_tor').innerHTML = factorHTML(r.is_tor);
        document.getElementById('ipc_hosting').innerHTML = factorHTML(r.is_hosting);
        document.getElementById('ipc_mobile').innerHTML = factorHTML(r.is_mobile);

        // Risk score
        const score = r.risk_score || 0;
        document.getElementById('ipc_risk_score').textContent = score + ' / 100';
        const bar = document.getElementById('ipc_risk_bar');
        bar.style.width = Math.min(100, score) + '%';
        bar.className = 'risk-bar-fill';
        if (score <= 15) bar.classList.add('risk-vlow');
        else if (score <= 33) bar.classList.add('risk-low');
        else if (score <= 66) bar.classList.add('risk-med');
        else if (score <= 85) bar.classList.add('risk-high');
        else bar.classList.add('risk-vhigh');

        const labelEl = document.getElementById('ipc_risk_label');
        labelEl.textContent = r.risk_label || '-';
        if (score <= 33) labelEl.style.color = 'var(--accent-green)';
        else if (score <= 66) labelEl.style.color = 'var(--accent-yellow)';
        else labelEl.style.color = 'var(--accent-red)';

        document.getElementById('ipc_time').textContent = data.timestamp || '-';

        // Compact Media unlock tiles (Chips)
        const grid = document.getElementById('unlock_grid');
        grid.innerHTML = '';
        (data.media || []).forEach(m => {
            const icon = MEDIA_ICONS[m.name] || '🌐';
            let statusClass, statusText;
            if (m.status === 'unlocked') { statusClass = 'unlock-yes'; statusText = '✅ 解锁'; }
            else if (m.status === 'blocked') { statusClass = 'unlock-no'; statusText = '❌ 屏蔽'; }
            else { statusClass = 'unlock-fail'; statusText = '⚠️ 未知'; }
            const regionText = m.region ? ` (${m.region})` : '';
            grid.innerHTML += `
                <div class="unlock-tile">
                    <div class="unlock-tile-left">
                        <span class="unlock-tile-icon">${icon}</span>
                        <span class="unlock-tile-name">${m.name}</span>
                    </div>
                    <div class="unlock-tile-status ${statusClass}">${statusText}${regionText}</div>
                </div>`;
        });
    }

    async function fetchIPCheck(force) {
        const btn = document.getElementById('ipcheck_btn');
        const spinner = document.getElementById('ipcheck_spinner');
        const btnText = document.getElementById('ipcheck_btn_text');
        btn.disabled = true;
        spinner.style.display = 'inline-block';
        btnText.textContent = '检测中...';
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
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            logger.info("Loaded SSL certificate chain: %s", cert_file)
        except Exception as e:
            logger.warning("Failed to load SSL cert chain: %s", e)
            ssl_ctx = None

    if ssl_ctx:
        logger.info("Starting HTTPS Werkzeug Server on 0.0.0.0:8080 (SSL enabled)")
        try:
            server = make_server("0.0.0.0", 8080, app, threaded=True, ssl_context=ssl_ctx)
            server.serve_forever()
        except Exception as e:
            logger.warning("Failed to start HTTPS server, falling back to HTTP: %s", e)
            app.run(host="0.0.0.0", port=8080)
    else:
        logger.info("Starting HTTP Werkzeug Server on 0.0.0.0:8080")
        app.run(host="0.0.0.0", port=8080)



