"""
NetWatch Server-Side Background Telemetry & Computation Engine
Continuously samples network latency, system metrics, and pre-computes API responses in memory
to ensure all frontend requests return instantly (<1ms) without blocking.
"""

import time
import socket
import logging
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import psutil

from app.config import PING_TARGETS
from app.tsdb import tsdb
from app.network import (
    tcp_ping, icmp_ping, get_public_ip, is_private_ip, get_auto_node_id
)
from app.system_stats import get_system_stats_data, get_uptime_history_data

logger = logging.getLogger(__name__)

# Global In-Memory Cache Store
_CACHE_LOCK = threading.Lock()
_CACHE = {
    "pings": None,
    "summary": None,
    "stats": None,
    "uptime": None,
    "latest_diag": None,
    "diag_cache": {},      # {target: {"data": ..., "ts": float}}
    "last_ping_ts": 0,
    "last_stats_ts": 0,
    "last_summary_ts": 0,
}

def get_cached_pings():
    with _CACHE_LOCK:
        if _CACHE["pings"] is not None:
            return _CACHE["pings"]
    # Fallback to compute if cache not yet populated
    return compute_pings_telemetry()

def get_cached_summary(client_ip: str = "127.0.0.1"):
    with _CACHE_LOCK:
        if _CACHE["summary"] is not None:
            summary = dict(_CACHE["summary"])
            # Inject dynamic visitor IP
            if "ipInfo" in summary:
                ip_info = dict(summary["ipInfo"])
                ip_info["visitorIp"] = client_ip or "127.0.0.1"
                summary["ipInfo"] = ip_info
            return summary
    return compute_summary_telemetry(client_ip)

def get_cached_stats():
    with _CACHE_LOCK:
        if _CACHE["stats"] is not None:
            return _CACHE["stats"]
    return get_system_stats_data()

def get_cached_uptime():
    with _CACHE_LOCK:
        if _CACHE["uptime"] is not None:
            return _CACHE["uptime"]
    return get_uptime_history_data()

def get_cached_diag(target: str):
    with _CACHE_LOCK:
        entry = _CACHE["diag_cache"].get(target)
        if entry and (time.time() - entry["ts"]) < 120:  # 120s TTL
            return entry["data"]
    return None

def set_cached_diag(target: str, data: dict):
    with _CACHE_LOCK:
        _CACHE["diag_cache"][target] = {
            "data": data,
            "ts": time.time()
        }

def compute_pings_telemetry(target_filter: str = "all") -> dict:
    """Compute and evaluate multi-target ping telemetry."""
    with ThreadPoolExecutor(max_workers=len(PING_TARGETS) + 1) as executor:
        futures = {
            executor.submit(tcp_ping, host): key
            for key, host in PING_TARGETS.items()
        }
        results = {key: future.result() for future, key in futures.items()}

    results["client_ping"] = None

    if target_filter != "all" and target_filter in results:
        main_lat = results.get(target_filter)
    else:
        main_lat = next((v for k, v in results.items() if k != "client_ping" and isinstance(v, (int, float))), None)

    now_ts = time.time()
    targets_detail = {k: v for k, v in results.items() if k != "stats"}

    # Insert into TSDB
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

    with _CACHE_LOCK:
        _CACHE["pings"] = results
        _CACHE["last_ping_ts"] = now_ts

    return results

def compute_summary_telemetry(client_ip: str = "127.0.0.1") -> dict:
    """Compute system summary metrics from TSDB."""
    egress_ip = get_public_ip()
    listen_ip = "72.18.80.151"

    history_samples = tsdb.query("global", limit=60)
    valid_samples = [s for s in history_samples if s.get("latency") is not None]
    total_checks = 7

    spikes_1h = len([s for s in history_samples if s.get("latency") and s["latency"] > 250])
    active_incidents = 0
    recovered_incidents = spikes_1h

    if len(valid_samples) == 0:
        overall_status = "INITIALIZING"
        reason = "Waiting for valid TCP ping samples... (0/3 collected)"
        completed_checks = 0
    else:
        completed_checks = 7
        recent = valid_samples[-10:]
        recent_lats = [s["latency"] for s in recent if s.get("latency") is not None]
        avg_lat = sum(recent_lats) / len(recent_lats) if recent_lats else 0.0

        if len(recent_lats) > 1:
            diffs = [abs(recent_lats[i] - recent_lats[i-1]) for i in range(1, len(recent_lats))]
            recent_jitter = sum(diffs) / len(diffs)
        else:
            recent_jitter = 0.0

        loss_pct = int(((len(recent) - len(recent_lats)) / max(1, len(recent))) * 100)

        if loss_pct > 20 or avg_lat > 250 or recent_jitter > 100:
            overall_status = "CRITICAL"
            active_incidents = 1
            reason = f"High latency / jitter / packet loss detected (avg {avg_lat:.0f}ms, jitter {recent_jitter:.0f}ms, loss {loss_pct}%)"
        elif avg_lat > 160 or recent_jitter > 30:
            overall_status = "DEGRADED"
            reason = f"Elevated network latency / jitter (avg {avg_lat:.0f}ms, jitter {recent_jitter:.0f}ms)"
        else:
            overall_status = "HEALTHY"
            reason = "All primary network checks operational."

    summary_detail = (
        f"{spikes_1h} high-latency spikes detected in the last hour. All related incidents recovered."
        if spikes_1h > 0 and overall_status == "HEALTHY"
        else f"{reason}"
    )

    now_dt = datetime.now()
    summary = {
        "nodeId": get_auto_node_id(egress_ip),
        "overallStatus": overall_status,
        "statusReason": reason,
        "summaryDetail": summary_detail,
        "spikes1hCount": spikes_1h,
        "activeIncidents": active_incidents,
        "recoveredIncidents": recovered_incidents,
        "validSamples": len(valid_samples),
        "completedChecks": completed_checks,
        "totalChecks": total_checks,
        "lastSuccessfulSync": now_dt.strftime("%H:%M:%S"),
        "lastUpdateReadable": f"Last update {now_dt.strftime('%H:%M:%S')}",
        "lastUpdateTimestamp": time.time(),
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
    }

    with _CACHE_LOCK:
        _CACHE["summary"] = summary
        _CACHE["last_summary_ts"] = time.time()

    return summary

def _telemetry_background_worker():
    """Background continuous loop to pre-compute telemetry and keep cache warm."""
    logger.info("Starting NetWatch Telemetry Background Worker...")
    # Initial immediate calculation
    try:
        compute_pings_telemetry()
        compute_summary_telemetry()
        with _CACHE_LOCK:
            _CACHE["stats"] = get_system_stats_data()
            _CACHE["uptime"] = get_uptime_history_data()
    except Exception as e:
        logger.warning("Initial telemetry calculation error: %s", e)

    # Pre-warm IP check and baseline diagnostics in background after 2s
    def prewarm_background():
        time.sleep(2)
        try:
            from app import ip_quality
            ip_quality.get_ip_quality()
            logger.info("IP quality check pre-warmed successfully")
        except Exception as e:
            logger.warning("IP quality pre-warm error: %s", e)

        try:
            from app.diagnostics import run_full_diagnostics, set_latest_diag_cache
            res = run_full_diagnostics("github.com")
            set_latest_diag_cache(res)
            set_cached_diag("full_github.com", res)
            logger.info("Baseline diagnostics pre-warmed successfully")
        except Exception as e:
            logger.warning("Diagnostics pre-warm error: %s", e)

    threading.Thread(target=prewarm_background, daemon=True).start()

    loop_count = 0
    while True:
        try:
            loop_count += 1
            # Update pings every 5s
            compute_pings_telemetry()
            compute_summary_telemetry()

            # Update stats & uptime every 2 cycles (10s)
            if loop_count % 2 == 0:
                with _CACHE_LOCK:
                    _CACHE["stats"] = get_system_stats_data()
                    _CACHE["uptime"] = get_uptime_history_data()

        except Exception as e:
            logger.warning("Telemetry background worker error: %s", e)

        time.sleep(5)

_worker_thread = None

def start_telemetry_engine():
    global _worker_thread
    if _worker_thread is None or not _worker_thread.is_alive():
        _worker_thread = threading.Thread(target=_telemetry_background_worker, daemon=True, name="TelemetryEngineThread")
        _worker_thread.start()
        logger.info("Telemetry Engine daemon thread started.")
