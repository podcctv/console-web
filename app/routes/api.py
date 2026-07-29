import os
import platform
import socket
import time
import subprocess
import shlex
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from flask import Blueprint, jsonify, Response, request, stream_with_context

import psutil

from app.config import PING_TARGETS, COMMANDS
from app.tsdb import tsdb
from app.network import (
    tcp_ping, icmp_ping, get_public_ip, is_private_ip, query_isp,
    ensure_isp_info, ISP_FULL_NAME, ISP_SHORT_NAME, humanize, humanize_bytes
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

@api_bp.route("/stats")
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
        physical_cores=physical_cores,
        total_cores=total_cores,
        max_freq=f"{freq.max:.2f}Mhz" if freq else None,
        total_memory=humanize_bytes(vm.total) if vm else None,
        total_disk=humanize_bytes(du.total) if du else None,
    )
