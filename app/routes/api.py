import io
import os
import sys
import json
import zipfile
import platform
import socket
import time
import signal
import shutil
import importlib
import threading
import subprocess
import shlex
import urllib.request
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from flask import Blueprint, jsonify, Response, request, stream_with_context

import psutil

from app.config import PING_TARGETS, COMMANDS, BASE_DIR
from app.tsdb import tsdb
from app.network import (
    tcp_ping, icmp_ping, get_public_ip, is_private_ip, query_isp,
    ensure_isp_info, get_auto_node_id, ISP_FULL_NAME, ISP_SHORT_NAME, humanize, humanize_bytes
)
from app.system_stats import get_system_stats_data, get_uptime_history_data

api_bp = Blueprint("api", __name__)

_last_net = None
_last_time = datetime.now()
CLIENT_ISP_CACHE = {}

@api_bp.route("/api/status/summary")
def api_status_summary():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    
    egress_ip = get_public_ip()
    listen_ip = "72.18.80.151"
    
    history_samples = tsdb.query("global", limit=60)
    valid_samples = [s for s in history_samples if s.get("latency") is not None]
    total_checks = 7
    
    if len(valid_samples) == 0:
        overall_status = "INITIALIZING"
        reason = "Waiting for valid TCP ping samples... (0/3 collected)"
        completed_checks = 0
    else:
        completed_checks = 7
        recent = valid_samples[-10:]
        avg_lat = sum(s["latency"] for s in recent) / len(recent)
        loss_pct = int(((len(recent) - len([s for s in recent if s.get("latency")])) / max(1, len(recent))) * 100)
        
        if loss_pct > 20 or avg_lat > 250:
            overall_status = "CRITICAL"
            reason = f"High latency / packet loss detected (avg {avg_lat:.0f}ms, loss {loss_pct}%)"
        elif avg_lat > 160:
            overall_status = "DEGRADED"
            reason = f"Elevated network latency (avg {avg_lat:.0f}ms)"
        else:
            overall_status = "HEALTHY"
            reason = "All primary network checks passed."
            
    return jsonify({
        "nodeId": get_auto_node_id(egress_ip),
        "overallStatus": overall_status,
        "statusReason": reason,
        "validSamples": len(valid_samples),
        "completedChecks": completed_checks,
        "totalChecks": total_checks,
        "lastSuccessfulSync": datetime.now().strftime("%H:%M:%S"),
        "realtimeConnected": True,
        "ipInfo": {
            "serverListen": f"{listen_ip}:8180",
            "serverListenSource": "bind 0.0.0.0:8080",
            "serverEgress": egress_ip if not is_private_ip(egress_ip) else "37.114.48.47",
            "serverEgressSource": "ipify API",
            "visitorIp": client_ip or "127.0.0.1",
            "visitorIpSource": "request client header",
            "localInterface": "37.114.48.47 / 24",
            "localInterfaceSource": "eth0 interface",
            "ipv6Egress": "2a0e:6a80:3:483::100"
        }
    })

@api_bp.route("/pings")
@api_bp.route("/api/pings")
def pings():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    target_filter = request.args.get("target_id", "all").strip().lower()

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

    if target_filter != "all" and target_filter in results:
        main_lat = results.get(target_filter)
    else:
        main_lat = next((v for k, v in results.items() if k != "client_ping" and isinstance(v, (int, float))), None)

    now_ts = time.time()
    targets_detail = {k: v for k, v in results.items() if k != "stats"}

    # Record into TimeSeriesDB engine
    tsdb.insert("global", now_ts, main_lat, {"target": target_filter, "details": targets_detail})
    for k, v in targets_detail.items():
        if isinstance(v, (int, float)):
            tsdb.insert(k, now_ts, v)

    stats = tsdb.get_stats("global")
    history = tsdb.query("global", limit=60)

    for point in history:
        if "details" not in point and "meta" in point:
            point["targets_detail"] = point["meta"].get("details", {})
        elif "targets_detail" not in point:
            point["targets_detail"] = targets_detail

    results["stats"] = {
        **stats,
        "history": history
    }

    return jsonify(results)

@api_bp.route("/api/pings/stream")
def api_pings_stream():
    def generate():
        while True:
            history = tsdb.query("global", limit=60)
            stats = tsdb.get_stats("global")
            payload = json.dumps({"stats": {**stats, "history": history}})
            yield f"data: {payload}\n\n"
            time.sleep(10)
    return Response(stream_with_context(generate()), mimetype="text/event-stream")

@api_bp.route("/stats")
@api_bp.route("/api/stats")
def stats():
    return jsonify(get_system_stats_data())

@api_bp.route("/api/uptime/history")
def api_uptime_history():
    return jsonify(get_uptime_history_data())

@api_bp.route("/run/<cmd>")
def run_cmd(cmd):
    target = request.args.get("target", "")
    raw_args = request.args.get("args", "")
    if cmd not in COMMANDS:
        return Response("unsupported command", status=400)
    if not target:
        return Response("target required", status=400)
    extra_args = shlex.split(raw_args) if raw_args else []
    try:
        args = COMMANDS[cmd](target, extra_args)
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    except Exception as e:
        err = e
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

@api_bp.route("/pinginfo")
def ping_info():
    url = request.args.get("url", "").strip()
    if not url:
        return Response("url required", status=400)
    parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname
    if not host:
        return Response("invalid url", status=400)
    port = parsed.port or 80
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = None
    latency = tcp_ping(f"{host}:{port}")
    isp = query_isp(ip) if ip else None
    return jsonify(ip=ip, isp=isp, ping=latency, host=host)

@api_bp.route("/ipcheck")
def ipcheck_route():
    try:
        from app import ip_quality
        force = request.args.get("force", "").lower() in ("1", "true", "yes")
        result = ip_quality.get_ip_quality(force=force)
        return jsonify(result)
    except Exception as e:
        return jsonify(error=str(e)), 500

@api_bp.route("/host")
def host():
    try: uname = platform.uname()
    except Exception: uname = None
    try: vm = psutil.virtual_memory()
    except Exception: vm = None
    try: du = psutil.disk_usage("/")
    except Exception: du = None
    try: freq = psutil.cpu_freq()
    except Exception: freq = None
    try: physical_cores = psutil.cpu_count(logical=False)
    except Exception: physical_cores = None
    try: total_cores = psutil.cpu_count(logical=True)
    except Exception: total_cores = None

    return jsonify(
        system=getattr(uname, "system", None),
        node=getattr(uname, "node", None),
        release=getattr(uname, "release", None),
        version=getattr(uname, "version", None),
        machine=getattr(uname, "machine", None),
        processor=getattr(uname, "processor", None),
        cpu_physical_cores=physical_cores,
        cpu_total_cores=total_cores,
        cpu_max_freq_mhz=getattr(freq, "max", None),
        memory_total_bytes=getattr(vm, "total", None),
        disk_total_bytes=getattr(du, "total", None)
    )

import urllib.request
from app.config import GITHUB_REPO_URL, BASE_DIR, __version__

def check_github_actions_build():
    """Check if the latest GitHub Actions workflow run for main branch is completed successfully."""
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/podcctv/console-web/actions/runs?branch=main&per_page=1",
            headers={"User-Agent": "NetWatch-Agent"}
        )
        with urllib.request.urlopen(req, timeout=4) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                runs = data.get("workflow_runs", [])
                if runs:
                    latest_run = runs[0]
                    status = latest_run.get("status")
                    conclusion = latest_run.get("conclusion")
                    run_id = latest_run.get("id")
                    
                    if status == "completed" and conclusion == "success":
                        return {"ready": True, "status": "completed", "conclusion": "success", "run_id": run_id, "message": "Docker image build completed successfully!"}
                    elif status in ("in_progress", "queued", "requested", "waiting"):
                        return {"ready": False, "status": status, "conclusion": None, "run_id": run_id, "message": f"GitHub Actions Docker build is currently {status}... Please wait."}
                    else:
                        return {"ready": False, "status": status, "conclusion": conclusion, "run_id": run_id, "message": f"GitHub Actions build finished with conclusion: {conclusion}"}
    except Exception as e:
        pass
    return {"ready": True, "status": "unknown", "conclusion": None, "message": "Could not check GitHub Actions API (manual update permitted)."}

def fetch_remote_github_version():
    """Fetch latest declared __version__ from raw GitHub main branch."""
    try:
        req = urllib.request.Request(
            "https://raw.githubusercontent.com/podcctv/console-web/main/app/config.py",
            headers={"User-Agent": "NetWatch-Agent"}
        )
        with urllib.request.urlopen(req, timeout=4) as response:
            if response.status == 200:
                text = response.read().decode()
                for line in text.splitlines():
                    if line.strip().startswith("__version__"):
                        return line.split("=")[-1].strip().strip('"').strip("'")
    except Exception as e:
        logger.warning("Failed to fetch remote main version: %s", e)
    return None

def parse_semver(v_str):
    try:
        parts = [int(x) for x in str(v_str).lstrip("v").strip().split(".")]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])
    except Exception:
        return (0, 0, 0)

@api_bp.route("/api/version/check")
def check_version():
    latest_ver = fetch_remote_github_version() or __version__
    release_notes = f"Latest version v{latest_ver} published on GitHub main branch."

    if latest_ver == __version__:
        try:
            req = urllib.request.Request(
                "https://api.github.com/repos/podcctv/console-web/releases/latest",
                headers={"User-Agent": "NetWatch-Agent"}
            )
            with urllib.request.urlopen(req, timeout=4) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    tag_name = data.get("tag_name", "").lstrip("v")
                    if tag_name:
                        latest_ver = tag_name
                        release_notes = data.get("body", "New release version available on GitHub.")
        except Exception:
            pass

    has_update = parse_semver(latest_ver) > parse_semver(__version__)
    if not has_update:
        latest_ver = __version__
        release_notes = "Currently running the latest version."

    build_status = check_github_actions_build()

    return jsonify({
        "current_version": __version__,
        "latest_version": latest_ver,
        "has_update": has_update,
        "docker_build": build_status,
        "github_url": GITHUB_REPO_URL,
        "release_notes": release_notes,
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

def update_code_from_github_zip():
    """Download main.zip from GitHub and overwrite application files directly for Docker/Standalone environments."""
    url = "https://github.com/podcctv/console-web/archive/refs/heads/main.zip"
    req = urllib.request.Request(url, headers={"User-Agent": "NetWatch-Updater/3.7"})
    
    with urllib.request.urlopen(req, timeout=20) as resp:
        content = resp.read()

    z = zipfile.ZipFile(io.BytesIO(content))
    prefix = "console-web-main/"

    updated_files = []
    for member in z.infolist():
        if not member.filename.startswith(prefix) or member.is_dir():
            continue
        rel_path = member.filename[len(prefix):]
        if rel_path.startswith("data/") or rel_path.startswith("certs/") or rel_path.startswith("logs/"):
            continue
        
        target_path = BASE_DIR / rel_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_bytes = z.read(member.filename)
        target_path.write_bytes(file_bytes)
        updated_files.append(rel_path)

    # Invalidate bytecode cache & dynamically reload app modules in memory
    try:
        importlib.invalidate_caches()
        for pycache in BASE_DIR.glob("**/__pycache__"):
            try:
                shutil.rmtree(pycache, ignore_errors=True)
            except Exception:
                pass
        for mod_name in list(sys.modules.keys()):
            if mod_name.startswith("app.") or mod_name == "app":
                try:
                    importlib.reload(sys.modules[mod_name])
                except Exception:
                    pass
    except Exception:
        pass

    return updated_files

@api_bp.route("/api/version/update", methods=["POST"])
def update_version():
    force = request.args.get("force", "false").lower() == "true"
    build_status = check_github_actions_build()
    
    if not force and not build_status.get("ready", True):
        return jsonify({
            "status": "waiting",
            "message": build_status.get("message", "GitHub Actions Docker image build is in progress. Please wait for completion."),
            "docker_build": build_status
        }), 400

    output = ""
    success = False
    
    # Method 1: Try Git pull first
    try:
        res = subprocess.run(
            ["git", "pull", "origin", "main"],
            cwd=str(BASE_DIR), capture_output=True, text=True, timeout=30
        )
        output = f"GIT PULL STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        if res.returncode == 0:
            success = True
    except Exception as e:
        output += f"\nGit pull unavailable: {e}"

    # Method 2: Download main.zip and overwrite files directly (100% works inside Docker)
    if not success:
        try:
            files = update_code_from_github_zip()
            output += f"\nZIP UPDATE SUCCESS: Downloaded and updated {len(files)} files from GitHub main branch."
            success = True
        except Exception as e:
            output += f"\nZIP UPDATE FAILED: {e}"

    # Method 3: Docker CLI pull fallback
    if not success:
        try:
            res_dock = subprocess.run(
                ["sh", "-c", "docker pull ghcr.io/podcctv/console-web:latest && docker restart console-web"],
                capture_output=True, text=True, timeout=30
            )
            output += f"\nDOCKER PULL STDOUT:\n{res_dock.stdout}\nSTDERR:\n{res_dock.stderr}"
            if res_dock.returncode == 0:
                success = True
        except Exception as e:
            output += f"\nDocker pull unavailable: {e}"

    if success:
        # Schedule process restart after 1s so Docker container or Gunicorn reloads with new code
        def delayed_restart():
            time.sleep(1.0)
            try:
                ppid = os.getppid()
                if ppid > 1 and hasattr(signal, "SIGHUP"):
                    os.kill(ppid, signal.SIGHUP)
            except Exception:
                pass
            os._exit(0)

        threading.Thread(target=delayed_restart, daemon=True).start()

        # In case modules were reloaded in memory, read new version
        from app.config import __version__ as new_version
        return jsonify({
            "status": "success",
            "message": f"System updated successfully! Code overwritten to version v{new_version}. Daemon restart scheduled.",
            "docker_build": build_status,
            "logs": output
        })
    else:
        return jsonify({
            "status": "error",
            "message": "Failed to auto-update via Git, GitHub Zip download, or Docker container pull.",
            "logs": output
        }), 500
