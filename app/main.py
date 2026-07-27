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

        /* Latency Ping Monitor */
        .ping-grid {
            display: flex; flex-direction: column; gap: 14px;
        }

        .ping-item {
            display: flex; flex-direction: column; gap: 6px; background: var(--input-bg);
            padding: 10px 14px; border-radius: 8px; border: 1px solid var(--card-border);
        }

        .ping-header {
            display: flex; justify-content: space-between; align-items: center; font-size: 0.85rem;
        }

        .ping-title { color: var(--text-white); font-weight: 600; display: flex; align-items: center; gap: 6px; }
        .ping-value { font-weight: 700; }
        
        .ping-chart-container {
            width: 100%; height: 36px; margin-top: 4px;
        }

        canvas.ping-chart {
            width: 100%; height: 100%; display: block;
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
                        <span class="info-key">磁盘 IO (读/写)</span>
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
                        <span class="info-key">操作系统</span>
                        <span class="info-value" id="os_val">-</span>
                    </div>
                    <div class="info-item">
                        <span class="info-key">系统架构</span>
                        <span class="info-value" id="arch_val">-</span>
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

            <!-- Card 3: Ping & Latency Dashboard -->
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
                            <span class="ping-value" id="client_ping_val">-</span>
                        </div>
                        <div class="ping-chart-container"><canvas id="client_ping_chart"></canvas></div>
                    </div>

                    <div class="ping-item">
                        <div class="ping-header">
                            <span class="ping-title">🟢 浙江联通 Ping</span>
                            <span class="ping-value" id="ping_cu_val">-</span>
                        </div>
                        <div class="ping-chart-container"><canvas id="ping_cu_chart"></canvas></div>
                    </div>

                    <div class="ping-item">
                        <div class="ping-header">
                            <span class="ping-title">🔵 浙江移动 Ping</span>
                            <span class="ping-value" id="ping_cm_val">-</span>
                        </div>
                        <div class="ping-chart-container"><canvas id="ping_cm_chart"></canvas></div>
                    </div>

                    <div class="ping-item">
                        <div class="ping-header">
                            <span class="ping-title">🟡 浙江电信 Ping</span>
                            <span class="ping-value" id="ping_ct_val">-</span>
                        </div>
                        <div class="ping-chart-container"><canvas id="ping_ct_chart"></canvas></div>
                    </div>
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
Try typing 'ping 8.8.8.8' or 'mtr 1.1.1.1' or 'lookup google.com'
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

    // Fetch stats
    async function fetchStats() {
        try {
            const res = await fetch('/stats');
            const data = await res.json();
            if (data.cpu !== null) updateProgress('cpu', data.cpu);
            if (data.memory !== null) updateProgress('memory', data.memory);
            if (data.disk !== null) updateProgress('disk', data.disk);
            
            document.getElementById('cuptime').textContent = data.container_uptime || '-';
            document.getElementById('huptime').textContent = data.host_uptime || '-';
            document.getElementById('cpu_cores').textContent = data.cores ? `${data.cores} 核` : '-';
            document.getElementById('load_val').textContent = `Load: ${data.load || 'N/A'}`;
            document.getElementById('disk_io').textContent = data.disk_io || '-';
            document.getElementById('net_io').textContent = data.net_io || '-';
            document.getElementById('ip_val').textContent = data.ip || '-';
            
            const cip = data.client_ip ? `${data.client_ip} [${data.client_isp || '未知'}]` : '局域网';
            document.getElementById('client_ip_val').textContent = cip;
        } catch (e) {
            console.error("Failed to fetch stats:", e);
        }
    }

    // Fetch Host details
    async function fetchHost() {
        try {
            const res = await fetch('/host');
            const data = await res.json();
            document.getElementById('os_val').textContent = data.system ? `${data.system} ${data.release || ''}` : '-';
            document.getElementById('arch_val').textContent = data.machine || '-';
            document.getElementById('mem_total_val').textContent = data.total_memory || '-';
            document.getElementById('disk_total_val').textContent = data.total_disk || '-';
        } catch(e) {}
    }

    // Ping history & Canvas charts
    const pingHistory = { client_ping: [], ping_cu: [], ping_cm: [], ping_ct: [] };

    function getPingColor(ms) {
        if (ms === null || ms === undefined) return '#ff3366';
        if (ms < 80) return '#00ff66';
        if (ms < 160) return '#ffcc00';
        return '#ff3366';
    }

    function renderCanvasChart(canvasId, historyData) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();
        
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);

        const width = rect.width;
        const height = rect.height;
        ctx.clearRect(0, 0, width, height);

        if (historyData.length === 0) return;

        const maxPing = Math.max(...historyData.map(v => v || 0), 100);
        const step = width / Math.max(historyData.length - 1, 1);

        // Draw grid lines
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, height / 2); ctx.lineTo(width, height / 2);
        ctx.stroke();

        // Draw area graph
        ctx.beginPath();
        historyData.forEach((val, i) => {
            const displayVal = val === null ? maxPing : val;
            const x = i * step;
            const y = height - (Math.min(displayVal, maxPing) / maxPing) * (height - 4);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });

        const lastVal = historyData[historyData.length - 1];
        ctx.strokeStyle = getPingColor(lastVal);
        ctx.lineWidth = 2;
        ctx.stroke();

        // Fill background glow
        ctx.lineTo(width, height);
        ctx.lineTo(0, height);
        ctx.closePath();
        ctx.fillStyle = lastVal === null ? 'rgba(255,51,102,0.1)' : 'rgba(0,255,102,0.08)';
        ctx.fill();
    }

    function updatePingUI(key, ms) {
        const valEl = document.getElementById(key + '_val');
        if (valEl) {
            if (ms === null || ms === undefined) {
                valEl.textContent = '超时/不可达';
                valEl.style.color = 'var(--accent-red)';
            } else {
                valEl.textContent = `${ms.toFixed(1)} ms`;
                valEl.style.color = getPingColor(ms);
            }
        }
        pingHistory[key].push(ms);
        if (pingHistory[key].length > 40) pingHistory[key].shift();
        renderCanvasChart(key + '_chart', pingHistory[key]);
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
            case 'help':
                appendOutput(`${PROMPT} ${text}\n` +
                    'Available Cyber Commands:\n' +
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

    // Initialize
    fetchStats();
    fetchHost();
    fetchPings();
    updateTimers();

    // Redraw charts on window resize
    window.addEventListener('resize', () => {
        Object.keys(pingHistory).forEach(key => renderCanvasChart(key + '_chart', pingHistory[key]));
    });
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
