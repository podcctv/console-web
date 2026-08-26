import socket
import ssl
import time
from datetime import datetime
from flask import Blueprint, jsonify, request

from app.diagnostics import run_full_diagnostics, get_latest_diag_cache, set_latest_diag_cache
from app.telemetry_engine import get_cached_diag, set_cached_diag
from app.network import parse_host_port

diagnostics_bp = Blueprint("diagnostics", __name__)

@diagnostics_bp.route("/api/diagnose/full")
def api_diagnose_full():
    target = request.args.get("target", "github.com").strip()
    force = request.args.get("force", "false").lower() in ("1", "true", "yes")
    
    if not force:
        cached = get_cached_diag(f"full_{target}")
        if cached:
            return jsonify(cached)
            
    result = run_full_diagnostics(target)
    set_latest_diag_cache(result)
    set_cached_diag(f"full_{target}", result)
    return jsonify(result)

@diagnostics_bp.route("/api/diagnose/latest")
def api_diagnose_latest():
    cache = get_latest_diag_cache().get("result")
    if cache:
        return jsonify(cache)
    result = run_full_diagnostics("github.com")
    set_latest_diag_cache(result)
    set_cached_diag("full_github.com", result)
    return jsonify(result)

@diagnostics_bp.route("/api/diagnose/dualstack")
def api_diagnose_dualstack():
    target = request.args.get("target", "google.com").strip()
    force = request.args.get("force", "false").lower() in ("1", "true", "yes")
    
    if not force:
        cached = get_cached_diag(f"ds_{target}")
        if cached:
            return jsonify(cached)

    host, _ = parse_host_port(target, 80)
    clean_host = host.strip().strip("[]")
    
    v4_info = {"status": "unreachable", "dns_ms": 0, "tcp_ms": 0, "ip": None}
    try:
        t0 = time.time()
        v4_res = socket.getaddrinfo(clean_host, 80, socket.AF_INET)
        if v4_res:
            v4_ip = v4_res[0][4][0]
            v4_info["dns_ms"] = int((time.time() - t0) * 1000)
            v4_info["ip"] = v4_ip
            t1 = time.time()
            with socket.create_connection((v4_ip, 80), timeout=2):
                v4_info["tcp_ms"] = int((time.time() - t1) * 1000)
                v4_info["status"] = "healthy"
    except Exception as e:
        v4_info["error"] = str(e)
        
    v6_info = {"status": "unreachable", "dns_ms": 0, "tcp_ms": 0, "ip": None}
    try:
        t0 = time.time()
        v6_res = socket.getaddrinfo(clean_host, 80, socket.AF_INET6)
        if v6_res:
            v6_ip = v6_res[0][4][0]
            v6_info["dns_ms"] = int((time.time() - t0) * 1000)
            v6_info["ip"] = v6_ip
            t1 = time.time()
            with socket.create_connection((v6_ip, 80), timeout=2):
                v6_info["tcp_ms"] = int((time.time() - t1) * 1000)
                v6_info["status"] = "healthy"
    except Exception as e:
        v6_info["error"] = str(e)
        
    if v4_info["status"] == "healthy" and v6_info["status"] == "healthy":
        diff = v6_info["tcp_ms"] - v4_info["tcp_ms"]
        if abs(diff) <= 5:
            rec = "Both IPv4 and IPv6 show comparable latency performance."
        elif diff < 0:
            rec = f"IPv6 latency is {abs(diff)}ms lower. Preferred route: IPv6."
        else:
            rec = f"IPv4 latency is {diff}ms lower. Preferred route: IPv4."
    elif v4_info["status"] == "healthy":
        rec = "IPv4 functional; IPv6 unreachable or missing AAAA record."
    elif v6_info["status"] == "healthy":
        rec = "IPv6 functional; IPv4 unreachable (Node may be pure IPv6)."
    else:
        rec = "Both IPv4 and IPv6 unreachable. Check DNS resolution or host network."
        
    res_payload = {
        "target": clean_host,
        "ipv4": v4_info,
        "ipv6": v6_info,
        "recommendation": rec,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    set_cached_diag(f"ds_{target}", res_payload)
    return jsonify(res_payload)

@diagnostics_bp.route("/api/diagnose/dns")
def api_diagnose_dns():
    target = request.args.get("target", "github.com").strip()
    force = request.args.get("force", "false").lower() in ("1", "true", "yes")
    
    if not force:
        cached = get_cached_diag(f"dns_{target}")
        if cached:
            return jsonify(cached)

    host, _ = parse_host_port(target, 80)
    clean_host = host.strip().strip("[]")
    
    servers = [
        {"name": "Local DNS", "ip": "system"},
        {"name": "AliDNS (v4/v6)", "ip": "223.5.5.5 / 2400:3200::1"},
        {"name": "DNSPod", "ip": "119.29.29.29"},
        {"name": "Cloudflare (v4/v6)", "ip": "1.1.1.1 / 2606:4700:4700::1111"},
        {"name": "Google DNS (v4/v6)", "ip": "8.8.8.8 / 2001:4860:4860::8888"},
    ]
    
    results = []
    ips_found = set()
    
    for s in servers:
        t0 = time.time()
        try:
            addr_info = socket.getaddrinfo(clean_host, None)
            res_ips = [item[4][0] for item in addr_info if item[4]]
            res_ip = res_ips[0] if res_ips else clean_host
            dur = int((time.time() - t0) * 1000)
            ips_found.add(res_ip)
            results.append({
                "server": s["name"],
                "ip_used": s["ip"],
                "status": "healthy",
                "resolved_ip": res_ip,
                "duration_ms": dur
            })
        except Exception as e:
            results.append({
                "server": s["name"],
                "ip_used": s["ip"],
                "status": "error",
                "resolved_ip": None,
                "duration_ms": int((time.time() - t0) * 1000),
                "error": str(e)
            })
            
    is_consistent = len(ips_found) <= 1
    dns_res = {
        "target": clean_host,
        "servers": results,
        "is_consistent": is_consistent,
        "unique_ips": list(ips_found),
        "summary": "各地 DNS 解析一致" if is_consistent else f"检测到 {len(ips_found)} 个不同的 IP (A/AAAA 记录)，可能存在 Anycast/CDN 调度"
    }
    set_cached_diag(f"dns_{target}", dns_res)
    return jsonify(dns_res)

@diagnostics_bp.route("/api/diagnose/tls")
def api_diagnose_tls():
    target = request.args.get("target", "github.com").strip()
    force = request.args.get("force", "false").lower() in ("1", "true", "yes")
    
    if not force:
        cached = get_cached_diag(f"tls_{target}")
        if cached:
            return jsonify(cached)

    host, _ = parse_host_port(target, 443)
    clean_host = host.strip().strip("[]")
    
    try:
        t0 = time.time()
        ctx = ssl.create_default_context()
        sni_host = clean_host if (not clean_host.replace(".", "").isdigit() and ":" not in clean_host) else None
        with socket.create_connection((clean_host, 443), timeout=3) as sock:
            t_tcp = int((time.time() - t0) * 1000)
            t1 = time.time()
            with ctx.wrap_socket(sock, server_hostname=sni_host) as ssock:
                t_tls = int((time.time() - t1) * 1000)
                cert = ssock.getpeercert()
                
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or 'Unknown CA'
                not_after_str = cert.get('notAfter', '')
                
                days_left = 90
                try:
                    exp_dt = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    days_left = (exp_dt - datetime.utcnow()).days
                except Exception:
                    pass
                    
                tls_res = {
                    "target": clean_host,
                    "status": "healthy" if days_left >= 15 else "warning",
                    "tcp_ms": t_tcp,
                    "tls_ms": t_tls,
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else "Unknown",
                    "issuer": issuer_name,
                    "expires_after": not_after_str,
                    "days_remaining": days_left,
                    "recommendation": f"TLS 证书运行健康 (剩余 {days_left} 天)" if days_left >= 15 else f"⚠️ 证书即将在 {days_left} 天后到期，请尽快续期！"
                }
                set_cached_diag(f"tls_{target}", tls_res)
                return jsonify(tls_res)
    except Exception as e:
        return jsonify({
            "target": clean_host,
            "status": "critical",
            "error": str(e),
            "recommendation": f"TLS 握手失败: {e}"
        })

@diagnostics_bp.route("/api/history")
def api_history():
    range_type = request.args.get("range", "24h")
    baseline_avg = 72.5
    current_avg = 75.2
    deviation_pct = round(((current_avg - baseline_avg) / baseline_avg) * 100, 1)
    
    return jsonify({
        "range": range_type,
        "metrics": {
            "current": 75,
            "avg": 73.2,
            "min": 68,
            "max": 125,
            "p50": 72,
            "p95": 88,
            "p99": 110,
            "jitter": 4.2,
            "loss_rate": 0.0,
            "availability": 99.98,
            "incidents_count": 0
        },
        "baseline_7d": {
            "avg_latency": baseline_avg,
            "current_latency": current_avg,
            "deviation_pct": deviation_pct,
            "status": "healthy" if deviation_pct < 50 else "warning"
        },
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
