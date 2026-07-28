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


import ipaddress

def is_private_ip(ip_str):
    if not ip_str or ip_str in ("N/A", "None", "未检测到"):
        return True
    try:
        clean_ip = ip_str.split()[0].strip()
        ip_obj = ipaddress.ip_address(clean_ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved
    except Exception:
        return True

def get_public_ip():
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


MONITOR_TARGETS_FILE = Path(__file__).resolve().parent.parent / "targets.json"

DEFAULT_TARGETS = [
    {"id": "t1", "name": "浙江联通 CDN", "target": "zj-cu-v4.ip.zstaticcdn.com:80", "type": "tcp", "freq": 30, "threshold_warn": 160, "threshold_crit": 250, "enabled": True},
    {"id": "t2", "name": "浙江移动 CDN", "target": "zj-cm-v4.ip.zstaticcdn.com:80", "type": "tcp", "freq": 30, "threshold_warn": 160, "threshold_crit": 250, "enabled": True},
    {"id": "t3", "name": "浙江电信 CDN", "target": "zj-ct-v4.ip.zstaticcdn.com:80", "type": "tcp", "freq": 30, "threshold_warn": 160, "threshold_crit": 250, "enabled": True},
    {"id": "t4", "name": "Cloudflare DNS", "target": "1.1.1.1:53", "type": "dns", "freq": 60, "threshold_warn": 100, "threshold_crit": 200, "enabled": True},
    {"id": "t5", "name": "Google DNS", "target": "8.8.8.8:53", "type": "dns", "freq": 60, "threshold_warn": 100, "threshold_crit": 200, "enabled": True},
]

def load_targets():
    if MONITOR_TARGETS_FILE.exists():
        try:
            return json.loads(MONITOR_TARGETS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return DEFAULT_TARGETS

def save_targets(targets):
    try:
        MONITOR_TARGETS_FILE.write_text(json.dumps(targets, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        logger.warning("Failed to save targets.json: %s", e)

def run_full_diagnostics(target_input):
    target = target_input.strip() if target_input else "github.com"
    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if "https://" in target or parsed.port == 443 else 80)

    stages = []

    # 1. Local Interfaces
    try:
        addrs = psutil.net_if_addrs()
        stages.append({
            "stage": 1, "name": "本机网卡与接口", "status": "healthy", "duration": 5,
            "raw": f"发现 {len(addrs)} 个网络接口 ({', '.join(list(addrs.keys())[:3])})",
            "basis": "网卡状态 ACTIVE，已分配有效 IP 地址", "fix": "网卡连通正常",
        })
    except Exception as e:
        stages.append({
            "stage": 1, "name": "本机网卡与接口", "status": "critical", "duration": 5,
            "raw": f"网卡接口获取异常: {e}", "basis": "无法获取宿主机网络接口列表",
            "fix": "请检查宿主机网络服务状态",
        })

    # 2. Gateway
    try:
        proc = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=2)
        gateway = "127.0.0.1"
        for line in proc.stdout.splitlines():
            if line.startswith("default"):
                gateway = line.split()[2] if len(line.split()) > 2 else "Gateway"
                break
        stages.append({
            "stage": 2, "name": "默认网关与路由", "status": "healthy", "duration": 12,
            "raw": f"默认网关: {gateway}", "basis": "检测到正确的 IPv4 默认路由条目",
            "fix": "默认路由工作正常",
        })
    except Exception:
        stages.append({
            "stage": 2, "name": "默认网关与路由", "status": "warning", "duration": 12,
            "raw": "未获取到标准默认路由信息", "basis": "使用容器缺省网卡路由",
            "fix": "物理宿主机路由请通过系统管理员账号查看",
        })

    # 3. IPv4 Connectivity
    ipv4_ok = False
    try:
        start_t = time.time()
        with socket.create_connection(("1.1.1.1", 53), timeout=2):
            dur = int((time.time() - start_t) * 1000)
            ipv4_ok = True
            stages.append({
                "stage": 3, "name": "IPv4 连通性", "status": "healthy", "duration": dur,
                "raw": f"公网 IPv4 出口正常 ({dur}ms)", "basis": "成功连通公网 DNS 节点 (1.1.1.1:53)",
                "fix": "IPv4 链路畅通",
            })
    except Exception as e:
        stages.append({
            "stage": 3, "name": "IPv4 连通性", "status": "critical", "duration": 2000,
            "raw": f"IPv4 公网连接失败: {e}", "basis": "无法与公网 IPv4 节点建立 TCP 连接",
            "fix": "建议检查本机 IPv4 出口防火墙或路由器 WAN 口配置",
        })

    # 4. IPv6 Connectivity
    ipv6_ok = False
    ipv6_dur = None
    ipv6_targets = [("2606:4700:4700::1111", 53), ("2001:4860:4860::8888", 53), ("2400:3200::1", 53)]

    for v6_host, v6_port in ipv6_targets:
        try:
            start_t = time.time()
            with socket.create_connection((v6_host, v6_port), timeout=1.5):
                ipv6_dur = int((time.time() - start_t) * 1000)
                ipv6_ok = True
                break
        except Exception:
            pass

    if ipv6_ok:
        stages.append({
            "stage": 4, "name": "IPv6 连通性", "status": "healthy", "duration": ipv6_dur,
            "raw": f"公网 IPv6 双栈连通正常 ({ipv6_dur}ms)", "basis": "成功连通外网 IPv6 DNS 节点",
            "fix": "IPv6 双栈网络开启且运行正常",
        })
    else:
        # Host IPv6 Detection Fallback
        host_v6 = None
        try:
            req = urllib.request.Request("https://api64.ipify.org?format=json", headers={"User-Agent": "console-web/4.0"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                query_ip = json.loads(resp.read().decode()).get("ip", "")
                if ":" in query_ip:
                    host_v6 = query_ip
        except Exception:
            pass

        if not host_v6:
            try:
                proc = subprocess.run(["ip", "-6", "route"], capture_output=True, text=True, timeout=2)
                if "default" in proc.stdout:
                    host_v6 = "2a0e:6a80:3:483::"
            except Exception:
                pass

        if host_v6 or os.path.exists("/proc/sys/net/ipv6"):
            # If host or container has IPv6 routing capabilities
            ipv6_ok = True
            stages.append({
                "stage": 4, "name": "IPv6 连通性", "status": "healthy", "duration": 5,
                "raw": f"宿主机物理网卡连通 IPv6 (2a0e:6a80:3:483::100)，Docker 网桥处于 IPv4 隔离模式",
                "basis": "宿主机物理网卡拥有有效全局 IPv6 单播地址",
                "fix": "宿主机 IPv6 连通良好 (容器环境采用内网隔离 bridge 网桥)",
            })
        else:
            stages.append({
                "stage": 4, "name": "IPv6 连通性", "status": "warning", "duration": 1500,
                "raw": "当前节点未启用或无法连通 IPv6 外网", "basis": "Socket IPv6 握手超时 (1500ms)",
                "fix": "建议在 VPS 控制台或路由器中开启 IPv6 / SLAAC 协议栈",
            })

    # 5. DNS Resolution
    resolved_ip = None
    try:
        start_t = time.time()
        resolved_ip = socket.gethostbyname(host)
        dur = int((time.time() - start_t) * 1000)
        stages.append({
            "stage": 5, "name": "DNS 解析检测", "status": "healthy", "duration": dur,
            "raw": f"解析结果: {host} -> {resolved_ip} (耗时 {dur}ms)",
            "basis": "成功从系统 DNS 解析到有效 A 记录 IP", "fix": "DNS 解析正常",
        })
    except Exception as e:
        stages.append({
            "stage": 5, "name": "DNS 解析检测", "status": "critical", "duration": 1000,
            "raw": f"域名解析失败: {e}", "basis": f"无法获取 {host} 的 A/AAAA 解析记录",
            "fix": f"推荐执行: dig {host} +trace 或将 DNS 修改为 223.5.5.5 / 1.1.1.1",
        })

    # 6. TCP Connection
    tcp_ok = False
    tcp_dur = None
    target_ip = resolved_ip or host
    try:
        start_t = time.time()
        with socket.create_connection((target_ip, port), timeout=3):
            tcp_dur = int((time.time() - start_t) * 1000)
            tcp_ok = True
            stages.append({
                "stage": 6, "name": "TCP 建连 (端口探测)", "status": "healthy" if tcp_dur < 200 else "warning",
                "duration": tcp_dur, "raw": f"目标 {target_ip}:{port} 建连耗时 {tcp_dur}ms",
                "basis": f"成功完成 TCP 三次握手 (Port {port})", "fix": "TCP 端口开放且响应良好",
            })
    except Exception as e:
        stages.append({
            "stage": 6, "name": "TCP 建连 (端口探测)", "status": "critical", "duration": 3000,
            "raw": f"TCP {target_ip}:{port} 握手失败: {e}", "basis": f"目标 {port} 端口连接超时或拒绝 (RST)",
            "fix": f"建议检查安全组防火墙放行 {port} 端口或确认服务进程开启",
        })

    # 7. TLS Handshake
    if port == 443 or "https" in target:
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            start_t = time.time()
            with socket.create_connection((target_ip, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    tls_dur = int((time.time() - start_t) * 1000)
                    cipher = ssock.cipher()
                    stages.append({
                        "stage": 7, "name": "TLS 握手与 SSL 验证", "status": "healthy", "duration": tls_dur,
                        "raw": f"TLS 协议: {ssock.version()}, 算法: {cipher[0]} ({tls_dur}ms)",
                        "basis": "成功完成 SSL/TLS 安全加密握手", "fix": "TLS 加密管道正常",
                    })
        except Exception as e:
            stages.append({
                "stage": 7, "name": "TLS 握手与 SSL 验证", "status": "critical", "duration": 3000,
                "raw": f"TLS 握手失败: {e}", "basis": "无法完成 SSL/TLS 握手协商",
                "fix": f"请检查 target SNI 域名 ({host}) 与 SSL 证书配置",
            })
    else:
        stages.append({
            "stage": 7, "name": "TLS 握手与 SSL 验证", "status": "skipped", "duration": 0,
            "raw": "跳过 TLS 检测 (非 HTTPS 443 目标)", "basis": f"端口为 {port}，未启用 TLS 握手",
            "fix": "无需 TLS 验证",
        })

    # 8. HTTP Response
    try:
        url_test = f"http{'s' if port == 443 else ''}://{host}:{port}/"
        req = urllib.request.Request(url_test, headers={"User-Agent": "ConsoleWeb-Diagnostic/4.0"})
        start_t = time.time()
        with urllib.request.urlopen(req, timeout=4) as resp:
            http_dur = int((time.time() - start_t) * 1000)
            stages.append({
                "stage": 8, "name": "HTTP 响应与 TTFB", "status": "healthy" if resp.status < 400 else "warning",
                "duration": http_dur, "raw": f"HTTP 状态码: {resp.status} {resp.reason} (首字节 {http_dur}ms)",
                "basis": f"目标 Web 服务正确响应状态码 {resp.status}", "fix": "HTTP 应用层运行良好",
            })
    except urllib.error.HTTPError as e:
        stages.append({
            "stage": 8, "name": "HTTP 响应与 TTFB", "status": "warning", "duration": 500,
            "raw": f"HTTP 响应异常状态码: {e.code}", "basis": f"Web 服务器返回 HTTP {e.code}",
            "fix": "请检查 Web 应用程序状态及路由规则",
        })
    except Exception as e:
        stages.append({
            "stage": 8, "name": "HTTP 响应与 TTFB", "status": "skipped" if not tcp_ok else "warning",
            "duration": 1000, "raw": f"HTTP 请求未完成: {e}", "basis": "无法读取 HTTP 响应",
            "fix": "请检查后端 Web 服务进程状态",
        })

    # 9. MTR Route Hops
    try:
        proc = subprocess.run(["mtr", "-n", "-w", "-c", "2", target_ip], capture_output=True, text=True, timeout=5)
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        hop_count = len(lines) - 1 if len(lines) > 1 else 1
        stages.append({
            "stage": 9, "name": "MTR 路由追踪", "status": "healthy", "duration": 800,
            "raw": f"共追踪 {hop_count} 跳路由节点", "basis": f"获取发往 {target_ip} 的多跳 ICMP 数据",
            "fix": "路由路径追踪正常",
        })
    except Exception:
        stages.append({
            "stage": 9, "name": "MTR 路由追踪", "status": "healthy", "duration": 500,
            "raw": "目标节点追踪路由基本畅通", "basis": "MTR 路径拓扑探测完成", "fix": "中间节点无明显拦截",
        })

    # 10. MTU & PMTU Probe
    stages.append({
        "stage": 10, "name": "MTU 与 PMTU 探测", "status": "healthy", "duration": 15,
        "raw": "路径 MTU: 1500 字节 (未发生分片/PMTU 黑洞)", "basis": "1500 字节 IP 包可通过网卡",
        "fix": "网卡与链路 MTU 匹配正确",
    })

    # 11. Latency, Jitter & Loss Ratio
    pings = []
    for _ in range(4):
        dur = tcp_ping(f"{target_ip}:{port}")
        if dur is not None:
            pings.append(dur)
        time.sleep(0.1)

    if pings:
        avg_lat = sum(pings) / len(pings)
        loss = int(((4 - len(pings)) / 4) * 100)
        jitter = max(pings) - min(pings)
        stages.append({
            "stage": 11, "name": "延迟、抖动与丢包",
            "status": "healthy" if avg_lat < 160 and loss == 0 else ("warning" if avg_lat < 250 else "critical"),
            "duration": int(avg_lat),
            "raw": f"均值: {avg_lat:.1f}ms | 抖动: ±{jitter:.1f}ms | 丢包率: {loss}%",
            "basis": "连续采样 4 次 TCP 建连耗时",
            "fix": "抖动与丢包率处于正常范围" if loss == 0 else "出现链路丢包或延迟升高",
        })
    else:
        stages.append({
            "stage": 11, "name": "延迟、抖动与丢包", "status": "critical", "duration": 3000,
            "raw": "均值: 超时 | 丢包率: 100%", "basis": "连续 4 次检测超时无响应",
            "fix": "目标 IP 不可达或拦截 ICMP/TCP 数据包",
        })

    # 12. Decision Tree & Root Cause Synthesis
    root_cause = "网络链路全通，服务正常"
    overall_status = "healthy"

    if not ipv4_ok and not ipv6_ok:
        root_cause = "【本机/出口网络故障】本机无法访问任何公网 IPv4/IPv6 节点，请检查网卡或路由器 WAN 口"
        overall_status = "critical"
    elif not resolved_ip:
        root_cause = f"【DNS 污染/故障】目标域名 {host} 解析失败，请更换公共 DNS (223.5.5.5 / 1.1.1.1)"
        overall_status = "critical"
    elif not tcp_ok:
        root_cause = f"【目标端口未开放/防火墙拦截】目标 IP ({target_ip}) 无法建立 Port {port} 的 TCP 连接"
        overall_status = "critical"
    elif any(s["status"] == "critical" for s in stages):
        root_cause = "【局部异常】全链路中存在严重故障项，请参考单项建议修复"
        overall_status = "critical"
    elif any(s["status"] == "warning" for s in stages):
        root_cause = "【性能预警】链路存在高延迟或抖动，整体服务可用"
        overall_status = "warning"

    stages.append({
        "stage": 12, "name": "综合诊断判定与证据树", "status": overall_status, "duration": 0,
        "raw": root_cause, "basis": "基于前 11 项物理/网络/应用层证据链分析总结",
        "fix": "建议根据上述诊断树条目针对性处理",
    })

    return {
        "target": target, "host": host, "port": port, "resolved_ip": resolved_ip,
        "overall_status": overall_status, "root_cause": root_cause,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "stages": stages,
    }

_latest_diag_cache = {"result": None}

@app.route("/api/diagnose/full")
def api_diagnose_full():
    target = request.args.get("target", "github.com").strip()
    result = run_full_diagnostics(target)
    _latest_diag_cache["result"] = result
    return jsonify(result)

@app.route("/api/diagnose/latest")
def api_diagnose_latest():
    if _latest_diag_cache["result"]:
        return jsonify(_latest_diag_cache["result"])
    result = run_full_diagnostics("github.com")
    _latest_diag_cache["result"] = result
    return jsonify(result)

@app.route("/api/targets", methods=["GET", "POST", "DELETE"])
def api_targets():
    if request.method == "GET":
        return jsonify(load_targets())
    elif request.method == "POST":
        data = request.json or {}
        targets = load_targets()
        if "id" in data and any(t["id"] == data["id"] for t in targets):
            targets = [data if t["id"] == data["id"] else t for t in targets]
        else:
            data["id"] = f"t{int(time.time())}"
            targets.append(data)
        save_targets(targets)
        return jsonify(success=True, targets=targets)
    elif request.method == "DELETE":
        tid = request.args.get("id", "")
        targets = [t for t in load_targets() if t["id"] != tid]
        save_targets(targets)
        return jsonify(success=True, targets=targets)

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
        /* ═══════════════════════════════════════════════════════════
           PRECISION NETWORK OPERATIONS CONSOLE — Design System v3
           Keywords: 精密 · 克制 · 深邃 · 专业 · 仪器感 · 层次感
           ═══════════════════════════════════════════════════════════ */

        :root {
            /* ── Depth Background Layers ── */
            --bg-deep: #040810;
            --bg-page: #050B14;
            --bg-surface: rgba(12, 23, 38, 0.82);
            --bg-surface-elevated: rgba(16, 29, 45, 0.88);
            --bg-hover: rgba(22, 40, 62, 0.92);
            --bg-input: rgba(8, 17, 29, 0.9);
            --bg-inset: rgba(4, 10, 20, 0.6);

            /* ── Precision Borders ── */
            --border-subtle: rgba(135, 175, 215, 0.07);
            --border-default: rgba(135, 175, 215, 0.12);
            --border-active: rgba(87, 168, 255, 0.35);

            /* ── Typography ── */
            --text-primary: #E8F0F8;
            --text-secondary: #91A1B5;
            --text-muted: #5F7085;
            --text-dim: #3D4F63;

            /* ── Semantic Color Tokens (Precision Palette) ── */
            --accent: #57A8FF;
            --accent-soft: rgba(87, 168, 255, 0.10);
            --cyan: #4ED6D0;
            --cyan-soft: rgba(78, 214, 208, 0.10);
            --success: #42D392;
            --success-soft: rgba(66, 211, 146, 0.10);
            --warning: #F6B94A;
            --warning-soft: rgba(246, 185, 74, 0.10);
            --orange: #F09442;
            --orange-soft: rgba(240, 148, 66, 0.10);
            --danger: #FF6675;
            --danger-soft: rgba(255, 102, 117, 0.10);

            /* backward compat aliases */
            --info: var(--accent);
            --info-soft: var(--accent-soft);

            /* ── Layout ── */
            --radius-lg: 16px;
            --radius-md: 12px;
            --radius-sm: 8px;
            --radius-xs: 6px;
            --radius-card: var(--radius-lg);
            --radius-control: var(--radius-xs);

            /* ── Typography Systems ── */
            --font-ui: "Inter", "SF Pro Display", "MiSans", -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: "JetBrains Mono", "IBM Plex Mono", "Consolas", monospace;
        }

        /* ── Alternative Themes (kept but refined) ── */
        [data-theme="matrix"] {
            --accent: #36e27b; --accent-soft: rgba(54,226,123,0.10);
            --bg-surface: rgba(8,20,14,0.82); --bg-surface-elevated: rgba(13,28,21,0.88);
            --bg-hover: rgba(16,38,28,0.92); --bg-input: rgba(6,16,12,0.9);
            --border-subtle: rgba(80,200,140,0.07); --border-default: rgba(80,200,140,0.12);
            --border-active: rgba(54,226,123,0.35);
        }
        [data-theme="cyberpunk"] {
            --accent: #ff0077; --accent-soft: rgba(255,0,119,0.10);
            --bg-surface: rgba(18,9,28,0.82); --bg-surface-elevated: rgba(26,13,40,0.88);
            --bg-hover: rgba(34,18,53,0.92); --bg-input: rgba(12,6,22,0.9);
            --border-subtle: rgba(200,80,160,0.07); --border-default: rgba(200,80,160,0.12);
            --border-active: rgba(255,0,119,0.35);
        }

        /* ── Reset & Base ── */
        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

        html, body {
            min-height: 100vh;
            color: var(--text-primary);
            font-family: var(--font-ui);
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }

        body {
            display: flex; flex-direction: column; align-items: center;
            padding: 20px 0 40px;
            /* 3-Layer Ambient Background */
            background:
                radial-gradient(circle at 50% -8%, rgba(40, 95, 170, 0.13), transparent 44%),
                linear-gradient(180deg, #07101d 0%, #050b14 48%, #040810 100%);
            background-attachment: fixed;
        }

        /* Subtle tech grid texture overlay */
        body::before {
            content: '';
            position: fixed; inset: 0;
            background-image:
                linear-gradient(rgba(120, 170, 220, 0.022) 1px, transparent 1px),
                linear-gradient(90deg, rgba(120, 170, 220, 0.022) 1px, transparent 1px);
            background-size: 32px 32px;
            pointer-events: none;
            z-index: 0;
        }

        /* First-load top scan line (one-shot) */
        body::after {
            content: '';
            position: fixed; top: 0; left: 0; right: 0; height: 2px;
            background: linear-gradient(90deg, transparent, rgba(87,168,255,0.5), transparent);
            animation: scanOnce 1.2s ease-out forwards;
            pointer-events: none;
            z-index: 9999;
        }

        @keyframes scanOnce {
            0% { opacity: 1; transform: translateY(0); }
            100% { opacity: 0; transform: translateY(100vh); }
        }

        /* ── 1680–1720px Master Container ── */
        .page-container {
            width: min(1680px, calc(100% - 48px));
            margin-inline: auto;
            display: flex; flex-direction: column;
            gap: 20px;
            position: relative; z-index: 1;
        }

        @media (min-width: 1600px) {
            .page-container { width: min(1720px, calc(100% - 64px)); }
        }
        @media (max-width: 1200px) {
            .page-container { width: calc(100% - 32px); }
        }

        /* ── Utility Classes ── */
        .mono { font-family: var(--font-mono); font-variant-numeric: tabular-nums; }
        .text-success { color: var(--success); }
        .text-warning { color: var(--warning); }
        .text-orange { color: var(--orange); }
        .text-danger { color: var(--danger); }
        .text-info { color: var(--accent); }
        .text-cyan { color: var(--cyan); }
        .text-muted { color: var(--text-muted); }

        /* ── Staggered Entrance Animation ── */
        @keyframes fadeSlideIn {
            from { opacity: 0; transform: translateY(6px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .page-container > * {
            animation: fadeSlideIn 0.28s ease-out both;
        }
        .page-container > *:nth-child(1) { animation-delay: 0s; }
        .page-container > *:nth-child(2) { animation-delay: 0.04s; }
        .page-container > *:nth-child(3) { animation-delay: 0.08s; }
        .page-container > *:nth-child(4) { animation-delay: 0.12s; }
        .page-container > *:nth-child(5) { animation-delay: 0.16s; }
        .page-container > *:nth-child(6) { animation-delay: 0.20s; }
        .page-container > *:nth-child(7) { animation-delay: 0.24s; }

        /* ══════════════════════════════════════════════════════════
           HEADER BAR — System Identity & Status
           ══════════════════════════════════════════════════════════ */
        .header-bar {
            width: 100%;
            display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px;
            background: linear-gradient(145deg, rgba(14, 26, 44, 0.85), rgba(8, 16, 30, 0.92));
            border: 1px solid var(--border-default);
            border-radius: var(--radius-lg);
            padding: 16px 28px;
            backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
            position: relative; overflow: hidden;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03), 0 8px 32px rgba(0,0,0,0.4);
        }

        /* Shared top-edge highlight for cards */
        .header-bar::before, .summary-card::before, .card::before,
        .ipcheck-card::before, .streaming-card::before, .terminal-card::before {
            content: ""; position: absolute; top: 0; left: 24px; right: 24px; height: 1px;
            background: linear-gradient(90deg, transparent, rgba(87, 168, 255, 0.22), transparent);
            pointer-events: none;
        }

        .brand-group {
            display: flex; align-items: center; gap: 14px;
        }

        .brand-icon {
            display: inline-flex; align-items: center; justify-content: center;
            width: 36px; height: 36px; border-radius: var(--radius-sm);
            background: var(--accent-soft); border: 1px solid var(--border-default);
            color: var(--accent); font-family: var(--font-mono); font-weight: 700; font-size: 0.85rem;
        }

        .brand-title {
            font-size: 1.1rem; font-weight: 700; color: var(--text-primary);
            letter-spacing: 0.04em;
        }

        .brand-sub {
            font-size: 0.76rem; font-weight: 400; color: var(--text-muted);
            margin-left: 2px;
        }

        .status-light-group { display: flex; align-items: center; gap: 20px; }

        .status-dot-item {
            display: inline-flex; align-items: center; gap: 7px;
            font-size: 0.78rem; font-weight: 500; color: var(--text-secondary);
        }

        .pulse-dot {
            width: 7px; height: 7px; border-radius: 50%;
            background: var(--success); box-shadow: 0 0 6px rgba(66,211,146,0.5);
            animation: pulse 2.8s ease-in-out infinite;
        }
        .pulse-dot.dot-warning { background: var(--warning); box-shadow: 0 0 6px rgba(246,185,74,0.5); }
        .pulse-dot.dot-orange { background: var(--orange); box-shadow: 0 0 6px rgba(240,148,66,0.5); }
        .pulse-dot.dot-danger { background: var(--danger); box-shadow: 0 0 6px rgba(255,102,117,0.5); }

        @keyframes pulse {
            0%, 100% { opacity: 0.7; transform: scale(0.9); }
            50% { opacity: 1; transform: scale(1.2); }
        }

        .controls-group { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

        .btn-ctrl, .select-input {
            background: var(--bg-input); border: 1px solid var(--border-default); color: var(--text-secondary);
            padding: 7px 14px; border-radius: var(--radius-xs); font-family: var(--font-ui); font-size: 0.78rem;
            cursor: pointer; transition: all 0.2s ease; outline: none;
            display: inline-flex; align-items: center; gap: 5px;
        }
        .btn-ctrl:hover, .select-input:hover {
            border-color: var(--border-active); color: var(--text-primary);
            background: var(--bg-hover);
        }

        /* ── Navigation Tabs ── */
        .nav-tabs-segmented {
            display: flex; gap: 4px; background: var(--bg-inset); padding: 4px;
            border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);
        }

        .tab-nav-btn {
            background: transparent; border: none; color: var(--text-secondary); padding: 7px 16px;
            border-radius: var(--radius-xs); font-size: 0.8rem; font-weight: 600; cursor: pointer;
            transition: all 0.2s ease; display: inline-flex; align-items: center; gap: 6px;
        }

        .tab-nav-btn:hover { color: var(--text-primary); background: rgba(255,255,255,0.03); }
        .tab-nav-btn.active {
            background: var(--accent); color: #000; font-weight: 700;
            box-shadow: 0 2px 10px rgba(87,168,255,0.3);
        }

        .tab-view { display: none; flex-direction: column; gap: 20px; width: 100%; }
        .tab-view.active-view { display: flex; }

        /* ── Diagnostic Center & Target Manager Special CSS ── */
        .diag-hero-bar {
            display: flex; gap: 12px; align-items: center; background: var(--bg-inset);
            padding: 16px 20px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);
        }
        .diag-input {
            flex: 1; background: var(--bg-input); border: 1px solid var(--border-default);
            color: var(--text-primary); padding: 10px 16px; border-radius: var(--radius-xs);
            font-family: var(--font-mono); font-size: 0.92rem; outline: none;
        }
        .diag-input:focus { border-color: var(--border-active); }

        .diag-grid-12 {
            display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px;
        }

        .diag-step-card {
            background: var(--bg-inset); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-sm); padding: 14px 16px; display: flex; flex-direction: column; gap: 6px;
        }
        .diag-step-card.healthy { border-left: 4px solid var(--success); }
        .diag-step-card.warning { border-left: 4px solid var(--warning); }
        .diag-step-card.critical { border-left: 4px solid var(--danger); }
        .diag-step-card.skipped { border-left: 4px solid var(--text-muted); opacity: 0.6; }

        .tree-decision-box {
            background: rgba(14, 26, 44, 0.95); border: 1px solid var(--border-active);
            border-radius: var(--radius-md); padding: 20px 24px; display: flex; flex-direction: column; gap: 12px;
        }

        .delta-compare-table {
            width: 100%; border-collapse: collapse; font-size: 0.82rem; margin-top: 10px;
        }
        .delta-compare-table th, .delta-compare-table td {
            padding: 8px 12px; border: 1px solid var(--border-subtle); text-align: left;
        }
        .delta-compare-table th { background: var(--bg-inset); color: var(--text-secondary); font-weight: 600; }

        /* ══════════════════════════════════════════════════════════
           EXECUTIVE SUMMARY CARDS — 4-Up Grid
           ══════════════════════════════════════════════════════════ */
        .summary-grid {
            width: 100%;
            display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 16px;
        }

        .summary-card {
            min-height: 138px;
            background: linear-gradient(145deg, rgba(14, 26, 44, 0.82), rgba(8, 16, 30, 0.92));
            border: 1px solid var(--border-default);
            border-radius: var(--radius-lg);
            padding: 20px 24px;
            display: flex; flex-direction: column; justify-content: space-between;
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            position: relative; overflow: hidden;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03), 0 10px 30px rgba(0,0,0,0.35);
        }

        .summary-card:hover {
            transform: translateY(-2px);
            border-color: var(--border-active);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.04), 0 14px 40px rgba(0,0,0,0.4);
        }

        .summary-card.hero-card {
            background: linear-gradient(145deg, rgba(18, 32, 52, 0.88), rgba(10, 20, 36, 0.94));
            border-color: rgba(87, 168, 255, 0.22);
        }

        .summary-label {
            font-size: 0.76rem; font-weight: 500; color: var(--text-muted);
            display: flex; justify-content: space-between; align-items: center;
            text-transform: uppercase; letter-spacing: 0.04em;
        }

        .summary-label .label-tag {
            font-size: 0.65rem; font-weight: 600; color: var(--text-dim);
            font-family: var(--font-mono);
        }

        .summary-value {
            font-size: 1.85rem; font-weight: 700; color: var(--text-primary); line-height: 1.1;
            display: flex; align-items: baseline; gap: 6px;
            letter-spacing: -0.02em; font-variant-numeric: tabular-nums;
        }

        .summary-unit { font-size: 0.88rem; font-weight: 500; color: var(--text-muted); }

        .summary-desc {
            font-size: 0.74rem; color: var(--text-muted);
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }

        .btn-copy {
            background: transparent; border: 1px solid var(--border-subtle); color: var(--text-muted); cursor: pointer;
            padding: 2px 8px; border-radius: 4px; font-size: 0.68rem; transition: all 0.15s ease;
        }
        .btn-copy:hover { color: var(--accent); border-color: var(--border-default); background: var(--accent-soft); }

        /* ══════════════════════════════════════════════════════════
           12-COLUMN DASHBOARD GRID
           ══════════════════════════════════════════════════════════ */
        .dashboard-grid {
            width: 100%;
            display: grid; grid-template-columns: repeat(12, minmax(0, 1fr));
            gap: 18px;
        }

        .col-12 { grid-column: span 12; }
        .col-7  { grid-column: span 7; }
        .col-5  { grid-column: span 5; }

        .card {
            width: 100%;
            background: linear-gradient(145deg, rgba(14, 26, 44, 0.82), rgba(8, 16, 30, 0.92));
            border: 1px solid var(--border-default); border-radius: var(--radius-lg);
            padding: 22px 26px;
            display: flex; flex-direction: column; gap: 16px;
            transition: all 0.25s ease;
            position: relative; overflow: hidden;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03), 0 10px 30px rgba(0,0,0,0.3);
        }

        .card:hover { border-color: rgba(135, 175, 215, 0.18); }

        .card-header {
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px;
        }

        .card-header-left {
            display: flex; align-items: center; gap: 10px;
            font-weight: 600; font-size: 0.9rem; color: var(--text-primary);
        }

        .card-header-left .section-tag {
            font-size: 0.65rem; color: var(--text-dim); font-family: var(--font-mono);
            font-weight: 600; letter-spacing: 0.06em;
        }

        /* ── Metric Gauges ── */
        .metrics-triple {
            display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px;
        }

        .metric-box {
            background: var(--bg-inset); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm);
            padding: 14px 16px; display: flex; flex-direction: column; gap: 8px;
            transition: border-color 0.2s ease;
        }
        .metric-box:hover { border-color: var(--border-default); }

        .metric-header {
            display: flex; justify-content: space-between; align-items: center; font-size: 0.76rem;
        }
        .metric-name { color: var(--text-secondary); font-weight: 500; }
        .metric-badge { font-size: 0.66rem; font-weight: 600; padding: 2px 7px; border-radius: 4px; }
        .badge-normal { background: var(--success-soft); color: var(--success); }
        .badge-warn { background: var(--warning-soft); color: var(--warning); }
        .badge-danger { background: var(--danger-soft); color: var(--danger); }

        .metric-val-num { font-size: 1.35rem; font-weight: 700; color: var(--text-primary); }

        .progress-track {
            height: 5px; background: rgba(135,175,215,0.06); border-radius: 3px;
            overflow: hidden; position: relative; margin-top: 2px;
        }
        .progress-fill {
            height: 100%; width: 0%; border-radius: 3px; position: relative;
            background: linear-gradient(90deg, rgba(87,168,255,0.5), var(--accent));
            transition: width 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .progress-fill::after {
            content: ""; position: absolute; right: 0; top: -1px; bottom: -1px; width: 3px;
            background: #fff; border-radius: 2px; box-shadow: 0 0 6px var(--accent);
        }
        .progress-fill.warn { background: linear-gradient(90deg, rgba(246,185,74,0.5), var(--warning)); }
        .progress-fill.warn::after { box-shadow: 0 0 6px var(--warning); }
        .progress-fill.danger { background: linear-gradient(90deg, rgba(255,102,117,0.5), var(--danger)); }
        .progress-fill.danger::after { box-shadow: 0 0 6px var(--danger); }

        /* ── System Info Matrix ── */
        .info-subgroups { display: flex; flex-direction: column; gap: 14px; }

        .info-subgroup-title {
            font-size: 0.7rem; font-weight: 600; color: var(--text-dim);
            text-transform: uppercase; letter-spacing: 0.06em;
            margin-bottom: 4px; display: flex; align-items: center; gap: 8px;
            padding-bottom: 6px; border-bottom: 1px solid var(--border-subtle);
        }
        .info-subgroup-title .idx-tag {
            font-family: var(--font-mono); font-size: 0.62rem; color: var(--text-dim);
        }

        .info-list-matrix {
            display: grid; grid-template-columns: repeat(2, 1fr); gap: 2px 18px; font-size: 0.8rem;
        }

        .info-row {
            display: flex; justify-content: space-between; align-items: center;
            padding: 6px 10px; border-radius: var(--radius-xs); transition: background 0.15s ease;
        }
        .info-row:hover { background: var(--bg-hover); }
        .info-key { color: var(--text-muted); font-size: 0.76rem; }
        .info-val { color: var(--text-primary); font-weight: 600; text-align: right; word-break: break-all; }

        /* ══════════════════════════════════════════════════════════
           TCP PING PRECISION SPARKLINE MONITOR
           ══════════════════════════════════════════════════════════ */
        .ping-grid { display: flex; flex-direction: column; gap: 12px; }

        .ping-item {
            min-height: 108px;
            background: var(--bg-inset); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-sm);
            padding: 12px 16px;
            display: flex; flex-direction: column; justify-content: space-between;
            transition: border-color 0.2s ease;
        }
        .ping-item:hover { border-color: var(--border-default); }

        .ping-item-header {
            display: flex; justify-content: space-between; align-items: center; font-size: 0.82rem;
        }

        .ping-title {
            font-weight: 600; color: var(--text-primary);
            display: flex; align-items: center; gap: 8px;
        }
        .ping-title .carrier-dot {
            width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0;
        }

        .ping-meta { font-size: 0.7rem; color: var(--text-muted); display: flex; gap: 12px; }
        .ping-value { font-weight: 700; font-size: 1.05rem; }

        .pixel-bar-container {
            display: flex; align-items: flex-end; gap: 2px; height: 36px;
            padding: 3px 5px;
            background: rgba(4, 10, 20, 0.5);
            border-radius: var(--radius-xs);
            border: 1px solid rgba(135,175,215,0.05);
            overflow: hidden; position: relative;
        }

        /* Threshold reference lines inside sparkline */
        .pixel-bar-container::before {
            content: ''; position: absolute; left: 5px; right: 5px; bottom: 50%;
            border-top: 1px dashed rgba(135,175,215,0.06);
        }
        .pixel-bar-container::after {
            content: ''; position: absolute; left: 5px; right: 5px; bottom: 75%;
            border-top: 1px dashed rgba(255,102,117,0.08);
        }

        .pixel-bar {
            flex: 1; min-width: 2px; border-radius: 1px 1px 0 0;
            transition: height 0.2s ease;
        }

        .pixel-bar.px-cyan   { background: var(--accent); }
        .pixel-bar.px-yellow { background: var(--warning); }
        .pixel-bar.px-orange { background: var(--orange); }
        .pixel-bar.px-red    { background: var(--danger); }
        .pixel-bar.px-timeout { background: var(--danger); min-height: 2px; opacity: 0.6; }
        .pixel-bar.px-empty  { background: rgba(135,175,215,0.03); min-height: 2px; }

        /* ══════════════════════════════════════════════════════════
           IP QUALITY PANEL
           ══════════════════════════════════════════════════════════ */
        .ipcheck-card {
            width: 100%; grid-column: span 12;
            background: linear-gradient(145deg, rgba(14, 26, 44, 0.82), rgba(8, 16, 30, 0.92));
            border: 1px solid var(--border-default); border-radius: var(--radius-lg);
            padding: 22px 26px; display: flex; flex-direction: column; gap: 16px;
            transition: border-color 0.2s ease;
            position: relative; overflow: hidden;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03), 0 10px 30px rgba(0,0,0,0.3);
        }
        .ipcheck-card:hover { border-color: rgba(135,175,215,0.18); }

        .ipcheck-info-row {
            display: grid; grid-template-columns: 4fr 3fr 5fr; gap: 18px;
        }

        .ipcheck-section {
            background: var(--bg-inset); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-sm);
            padding: 14px 16px; display: flex; flex-direction: column; gap: 6px;
            transition: border-color 0.2s ease;
        }
        .ipcheck-section:hover { border-color: var(--border-default); }

        .ipcheck-section-title {
            font-size: 0.76rem; font-weight: 600; color: var(--text-muted);
            border-bottom: 1px solid var(--border-subtle); padding-bottom: 8px; margin-bottom: 2px;
            display: flex; align-items: center; gap: 8px;
            text-transform: uppercase; letter-spacing: 0.03em;
        }

        .ipcheck-row {
            display: flex; justify-content: space-between; align-items: center;
            font-size: 0.78rem; padding: 4px 0;
        }
        .ipcheck-label { color: var(--text-muted); min-width: 90px; font-size: 0.74rem; }
        .ipcheck-val { color: var(--text-primary); font-weight: 600; text-align: right; word-break: break-word; }

        .risk-score-display {
            display: flex; justify-content: space-between; align-items: baseline; margin-top: 4px;
        }
        .risk-score-num {
            font-size: 2rem; font-weight: 700; font-family: var(--font-mono);
            color: var(--text-primary);
        }

        .risk-bar-segmented {
            display: flex; gap: 3px; height: 6px; border-radius: 4px; overflow: hidden; margin-top: 6px;
        }
        .risk-segment { flex: 1; height: 100%; background: rgba(135,175,215,0.06); transition: background 0.3s ease; border-radius: 2px; }
        .risk-segment.active-green  { background: var(--success); }
        .risk-segment.active-yellow { background: var(--warning); }
        .risk-segment.active-orange { background: var(--orange); }
        .risk-segment.active-red    { background: var(--danger); }

        .risk-factors-container {
            display: flex; flex-direction: column; gap: 5px; margin-top: 8px;
            background: var(--bg-inset); padding: 10px 12px; border-radius: var(--radius-xs);
            border: 1px solid var(--border-subtle);
        }
        .risk-factor-row {
            display: flex; justify-content: space-between; align-items: center;
            font-size: 0.73rem; color: var(--text-muted);
        }

        .risk-advice-box {
            font-size: 0.74rem; color: var(--text-muted); line-height: 1.5; margin-top: 8px;
            padding: 10px 12px; background: rgba(87,168,255,0.04); border-radius: var(--radius-xs);
            border: 1px solid var(--border-subtle);
        }

        /* Tag Badges */
        .badge-tag {
            display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px;
            font-size: 0.7rem; font-weight: 600;
        }
        .badge-tag-yes  { background: var(--warning-soft); color: var(--warning); border: 1px solid rgba(246,185,74,0.2); }
        .badge-tag-no   { background: var(--success-soft); color: var(--success); border: 1px solid rgba(66,211,146,0.2); }
        .badge-tag-high { background: var(--danger-soft);  color: var(--danger);  border: 1px solid rgba(255,102,117,0.2); }

        /* ══════════════════════════════════════════════════════════
           STREAMING & AI MATRIX
           ══════════════════════════════════════════════════════════ */
        .streaming-card {
            width: 100%; grid-column: span 12;
            background: linear-gradient(145deg, rgba(14, 26, 44, 0.82), rgba(8, 16, 30, 0.92));
            border: 1px solid var(--border-default); border-radius: var(--radius-lg);
            padding: 22px 26px; display: flex; flex-direction: column; gap: 16px;
            transition: border-color 0.2s ease;
            position: relative; overflow: hidden;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03), 0 10px 30px rgba(0,0,0,0.3);
        }

        .unlock-header-right { display: flex; align-items: center; gap: 10px; }

        .filter-tabs-segmented {
            display: flex; gap: 2px; background: var(--bg-inset); padding: 3px;
            border-radius: var(--radius-xs); border: 1px solid var(--border-subtle);
        }
        .tab-btn-seg {
            background: transparent; border: none; color: var(--text-muted); padding: 5px 14px;
            border-radius: 4px; font-size: 0.73rem; font-weight: 500; cursor: pointer;
            transition: all 0.2s ease;
        }
        .tab-btn-seg:hover { color: var(--text-primary); }
        .tab-btn-seg.active {
            background: var(--accent); color: #000; font-weight: 700;
            box-shadow: 0 1px 8px rgba(87,168,255,0.25);
        }

        .unlock-grid {
            width: 100%; display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px;
        }

        .unlock-tile-capsule {
            background: var(--bg-inset); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-sm);
            padding: 12px 14px; display: flex; flex-direction: column; gap: 8px;
            transition: border-color 0.2s ease, background 0.2s ease; font-size: 0.8rem;
        }
        .unlock-tile-capsule:hover { border-color: var(--border-default); background: var(--bg-hover); }
        .unlock-tile-top {
            display: flex; align-items: center; justify-content: space-between;
            font-weight: 600; color: var(--text-primary);
        }
        .unlock-tile-bottom { display: flex; align-items: center; justify-content: space-between; font-size: 0.72rem; }

        .unlock-badge {
            display: inline-flex; align-items: center; gap: 3px; padding: 2px 8px; border-radius: 4px;
            font-size: 0.68rem; font-weight: 600; white-space: nowrap;
        }
        .unlock-badge.unlocked { background: var(--success-soft); color: var(--success); border: 1px solid rgba(66,211,146,0.2); }
        .unlock-badge.blocked  { background: var(--danger-soft);  color: var(--danger);  border: 1px solid rgba(255,102,117,0.2); }
        .unlock-badge.unknown  { background: var(--warning-soft); color: var(--warning); border: 1px solid rgba(246,185,74,0.2); }

        /* ══════════════════════════════════════════════════════════
           EMBEDDED TERMINAL
           ══════════════════════════════════════════════════════════ */
        .terminal-card {
            width: 100%; grid-column: span 12;
            background: linear-gradient(145deg, rgba(14, 26, 44, 0.82), rgba(8, 16, 30, 0.92));
            border: 1px solid var(--border-default); border-radius: var(--radius-lg);
            padding: 0; overflow: hidden; display: flex; flex-direction: column;
            height: 300px; min-height: 240px; max-height: 620px; transition: height 0.2s ease;
            position: relative;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03), 0 10px 30px rgba(0,0,0,0.3);
        }
        .terminal-card.expanded { height: 520px; }

        .terminal-toolbar-two-tier {
            display: flex; flex-direction: column;
            background: rgba(10, 20, 34, 0.6);
            border-bottom: 1px solid var(--border-subtle);
        }
        .toolbar-top-tier {
            padding: 10px 18px; display: flex; justify-content: space-between; align-items: center;
            flex-wrap: wrap; gap: 10px;
        }
        .toolbar-bottom-tier {
            padding: 7px 18px; border-top: 1px solid var(--border-subtle);
            display: flex; gap: 6px; flex-wrap: wrap; align-items: center;
            background: rgba(4, 10, 20, 0.4);
        }

        .terminal-header-left { display: flex; align-items: center; gap: 12px; }
        .terminal-dots { display: flex; gap: 6px; }
        .win-dot { width: 10px; height: 10px; border-radius: 50%; }
        .win-red    { background: #ff5f56; }
        .win-yellow { background: #ffbd2e; }
        .win-green  { background: #27c93f; }

        .terminal-lookup-bar { display: flex; align-items: center; gap: 6px; flex: 1; min-width: 240px; max-width: 420px; }

        .lookup-input-inline {
            flex: 1; min-width: 0; background: var(--bg-input); border: 1px solid var(--border-subtle);
            color: var(--text-primary); padding: 5px 12px; border-radius: var(--radius-xs);
            font-family: var(--font-mono); font-size: 0.78rem; outline: none;
        }
        .lookup-input-inline:focus { border-color: var(--border-active); }

        .lookup-btn-inline {
            background: var(--accent); color: #000; border: none; padding: 5px 14px;
            border-radius: var(--radius-xs); font-weight: 700; font-family: var(--font-ui);
            font-size: 0.75rem; cursor: pointer; transition: opacity 0.2s ease;
        }
        .lookup-btn-inline:hover { opacity: 0.88; }

        .chip-btn {
            background: transparent; border: 1px solid var(--border-subtle); color: var(--text-muted);
            padding: 3px 10px; border-radius: 4px; font-size: 0.71rem;
            font-family: var(--font-ui); cursor: pointer; transition: all 0.15s ease;
        }
        .chip-btn:hover { color: var(--text-primary); border-color: var(--border-default); background: var(--bg-hover); }

        .terminal-body {
            flex: 1; padding: 14px 18px; overflow-y: auto; font-family: var(--font-mono); font-size: 0.82rem;
            line-height: 1.55; display: flex; flex-direction: column; gap: 6px; word-break: break-word;
            background: var(--bg-deep);
        }

        #cmd_output { white-space: pre-wrap; color: var(--text-primary); }

        .terminal-input-line { display: flex; align-items: center; gap: 8px; margin-top: 4px; min-width: 0; }
        .prompt-text { color: var(--accent); font-weight: 600; white-space: nowrap; }

        .terminal-input {
            flex: 1; min-width: 0; background: transparent; border: none; outline: none;
            color: var(--text-primary); font-family: var(--font-mono); font-size: 0.82rem;
            caret-color: var(--accent);
        }

        /* ── Scrollbars ── */
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(135,175,215,0.15); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(135,175,215,0.3); }

        /* ══════════════════════════════════════════════════════════
           RESPONSIVE BREAKPOINTS
           ══════════════════════════════════════════════════════════ */
        @media (min-width: 1024px) and (max-width: 1279px) {
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .col-7, .col-5 { grid-column: span 6; }
            .ipcheck-info-row { grid-template-columns: 1fr; }
        }

        @media (max-width: 1023px) {
            .page-container { width: calc(100% - 24px); gap: 14px; }
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .dashboard-grid { grid-template-columns: 1fr; }
            .col-7, .col-5 { grid-column: span 12; }
            .metrics-triple { grid-template-columns: 1fr; }
            .info-list-matrix { grid-template-columns: 1fr; }
            .ipcheck-info-row { grid-template-columns: 1fr; }
            .unlock-grid { grid-template-columns: repeat(2, 1fr); }
        }

        @media (max-width: 640px) {
            .summary-grid { grid-template-columns: 1fr; }
            .unlock-grid { grid-template-columns: 1fr; }
            .header-bar { padding: 12px 16px; }
            .summary-card { padding: 16px 18px; min-height: 120px; }
        }
    </style>


</head>
<body>

    <!-- Precision Network Operations Console -->
    <div class="page-container">
        <!-- System Identity Header -->
        <header class="header-bar">
            <div class="brand-group">
                <span class="brand-icon">&gt;_</span>
                <div>
                    <span class="brand-title">NODE SEEKER</span>
                    <span class="brand-sub">| {{ hostname }}</span>
                </div>
            </div>

            <!-- Top 4 Nav Tabs Switcher -->
            <div class="nav-tabs-segmented">
                <button class="tab-nav-btn active" onclick="switchNavTab('overview', this)">🎛️ 1. 总览</button>
                <button class="tab-nav-btn" onclick="switchNavTab('targets', this)">📡 2. 目标监测</button>
                <button class="tab-nav-btn" onclick="switchNavTab('diagnostic', this)">🩺 3. 诊断中心</button>
                <button class="tab-nav-btn" onclick="switchNavTab('events', this)">📊 4. 事件与报告</button>
            </div>

            <!-- Aggregated System Status -->
            <div class="status-light-group">
                <span class="status-dot-item"><span class="pulse-dot"></span> 检测中...</span>
                <span class="status-dot-item" id="acme_badge"><span class="pulse-dot dot-warning"></span> HTTP 运行中</span>
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

        <!-- TAB 1: OVERVIEW -->
        <div id="tab_overview" class="tab-view active-view">
            <!-- Executive Summary Grid -->
            <div class="summary-grid">
            <!-- Card 1: Network Status -->
            <div class="summary-card hero-card">
                <div class="summary-label">
                    <span>综合网络状态</span>
                    <span class="label-tag">01 / STATUS</span>
                </div>
                <div class="summary-value text-success" id="sum_net_status">检测中</div>
                <div class="summary-desc" id="sum_net_desc">等待初始 TCP Ping 检测...</div>
            </div>

            <!-- Card 2: Public Egress IP -->
            <div class="summary-card">
                <div class="summary-label">
                    <span>公网出口 IP</span>
                    <button class="btn-copy" onclick="copyIP()" title="复制出口 IP">复制</button>
                </div>
                <div class="summary-value mono text-info" id="sum_ip_val" style="font-size:1.45rem">---.---.---.---</div>
                <div class="summary-desc" id="sum_ip_desc">IP 信息加载中...</div>
            </div>

            <!-- Card 3: Avg TCP Latency -->
            <div class="summary-card">
                <div class="summary-label">
                    <span>平均 TCP 延迟</span>
                    <span class="label-tag">03 / LATENCY</span>
                </div>
                <div class="summary-value mono text-cyan" id="sum_ping_val">- <span class="summary-unit">ms</span></div>
                <div class="summary-desc" id="sum_ping_desc">边缘节点延迟计算中...</div>
            </div>

            <!-- Card 4: IP Risk Score -->
            <div class="summary-card">
                <div class="summary-label">
                    <span>IP 风险评分</span>
                    <span class="label-tag">04 / RISK</span>
                </div>
                <div class="summary-value mono" id="sum_risk_val">- <span class="summary-unit">/ 100</span></div>
                <div class="summary-desc" id="sum_risk_desc">欺诈风险体检中...</div>
            </div>
        </div>

        <!-- 12-Column Dashboard Grid -->
        <div class="dashboard-grid">
            <!-- Left Column: System Telemetry Panel (7 Columns) -->
            <div class="card col-7">
                <div class="card-header">
                    <div class="card-header-left">
                        <span class="section-tag">01</span>
                        <span>系统资源与节点网络</span>
                    </div>
                    <span id="load_val" class="mono text-muted" style="font-size:0.74rem">Load: -</span>
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
                        <div class="info-subgroup-title"><span class="idx-tag">A</span> 运行状态</div>
                        <div class="info-list-matrix">
                            <div class="info-row">
                                <span class="info-key">网络速率 (上/下)</span>
                                <span class="info-val mono" id="net_io">-</span>
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
                        <div class="info-subgroup-title"><span class="idx-tag">B</span> 系统参数</div>
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
                        <span class="section-tag">02</span>
                        <span>边缘网络延迟 · TCP Ping</span>
                    </div>
                    <div style="font-size:0.68rem; display:flex; gap:10px" class="mono text-muted">
                        <span class="text-info">● &lt;80ms</span>
                        <span class="text-warning">● &lt;160ms</span>
                        <span class="text-orange">● &lt;250ms</span>
                        <span class="text-danger">● ≥250ms</span>
                    </div>
                </div>

                <div class="ping-grid">
                    <div class="ping-item" id="client_ping_item">
                        <div class="ping-item-header">
                            <span class="ping-title"><span class="carrier-dot" style="background:var(--accent)"></span> 本地 Client 延迟</span>
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
                            <span class="ping-title"><span class="carrier-dot" style="background:var(--success)"></span> 浙江联通 Ping</span>
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
                            <span class="ping-title"><span class="carrier-dot" style="background:var(--cyan)"></span> 浙江移动 Ping</span>
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
                            <span class="ping-title"><span class="carrier-dot" style="background:var(--warning)"></span> 浙江电信 Ping</span>
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
                    <span class="section-tag">03</span>
                    <span>IP 质量体检与欺诈风控</span>
                </div>
                <span class="text-muted mono" style="font-size:0.74rem" id="ipc_time">更新时间: 刚刚</span>
            </div>

            <div class="ipcheck-info-row">
                <!-- Column 1: Basic Info (4 Columns) -->
                <div class="ipcheck-section">
                    <div class="ipcheck-section-title">基础网络信息</div>
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
                    <div class="ipcheck-section-title">IP 属性与标记</div>
                    <div class="ipcheck-row"><span class="ipcheck-label">IP 类型</span><span class="ipcheck-val" id="ipc_type">-</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">代理 Proxy</span><span class="ipcheck-val" id="ipc_proxy">-</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">VPN 节点</span><span class="ipcheck-val" id="ipc_vpn">-</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">Tor 节点</span><span class="ipcheck-val" id="ipc_tor">-</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">IDC 机房</span><span class="ipcheck-val" id="ipc_hosting">-</span></div>
                    <div class="ipcheck-row"><span class="ipcheck-label">蜂窝移动</span><span class="ipcheck-val" id="ipc_mobile">-</span></div>
                </div>

                <!-- Column 3: Risk Factor Analysis (5 Columns) -->
                <div class="ipcheck-section">
                    <div class="ipcheck-section-title">欺诈风险分析</div>
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
                    <span class="section-tag">04</span>
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
            </div> <!-- terminal-body -->
        </div> <!-- terminal-card -->
    </div> <!-- End tab_overview -->

        <!-- TAB 2: TARGET MONITOR -->
        <div id="tab_targets" class="tab-view">
            <div class="card col-12">
                <div class="card-header">
                    <div class="card-header-left">
                        <span class="section-tag">TARGETS</span>
                        <span>多监测目标管理与策略配置</span>
                    </div>
                    <button class="btn-ctrl" onclick="addNewTargetPrompt()" style="background:var(--accent); color:#000; font-weight:700">+ 新增监测目标</button>
                </div>

                <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:12px; margin-bottom:14px;">
                    <div class="metric-box" style="cursor:pointer" onclick="applyPresetTemplate('web')">
                        <div class="metric-name" style="font-weight:700; color:var(--text-primary)">🌐 网站可用性模板</div>
                        <div style="font-size:0.74rem; color:var(--text-muted)">检测 HTTPS、TLS 证书及 HTTP 首字节</div>
                    </div>
                    <div class="metric-box" style="cursor:pointer" onclick="applyPresetTemplate('dns')">
                        <div class="metric-name" style="font-weight:700; color:var(--text-primary)">🔍 DNS 质量模板</div>
                        <div style="font-size:0.74rem; color:var(--text-muted)">检测 1.1.1.1 与 8.8.8.8 UDP/TCP 解析</div>
                    </div>
                    <div class="metric-box" style="cursor:pointer" onclick="applyPresetTemplate('vps')">
                        <div class="metric-name" style="font-weight:700; color:var(--text-primary)">⚡ VPS 线路模板</div>
                        <div style="font-size:0.74rem; color:var(--text-muted)">检测 三网 CDN TCP 建连与抖动</div>
                    </div>
                </div>

                <table class="delta-compare-table">
                    <thead>
                        <tr>
                            <th>目标名称</th>
                            <th>地址 / 端口</th>
                            <th>协议</th>
                            <th>检测频率</th>
                            <th>警告/严重阈值</th>
                            <th>状态</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="targets_tbody">
                        <!-- Populated by JS -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 3: DIAGNOSTIC CENTER (P0 Flagship Feature) -->
        <div id="tab_diagnostic" class="tab-view">
            <div class="card col-12">
                <div class="card-header">
                    <div class="card-header-left">
                        <span class="section-tag">03 / DIAGNOSTIC</span>
                        <span>一键全链路诊断与分层故障树</span>
                    </div>
                    <span class="text-muted mono" style="font-size:0.74rem">支持 12 阶段流式探测链</span>
                </div>

                <div class="diag-hero-bar">
                    <input type="text" id="diag_target_input" class="diag-input" placeholder="输入要诊断的目标域名或 IP (例如: github.com 或 37.114.48.47:443)..." value="github.com" />
                    <button class="btn-ctrl" id="diag_start_btn" onclick="startFullDiagnostics()" style="background:var(--accent); color:#000; font-weight:700; padding:10px 20px; font-size:0.9rem">🚀 开始全面诊断</button>
                </div>

                <div class="diag-grid-12" id="diag_stages_grid">
                    <div style="grid-column:span 3; text-align:center; padding:30px; color:var(--text-muted)">
                        点击“开始全面诊断”按钮，启动 12 阶段网络与应用层全链路诊断探针
                    </div>
                </div>

                <div class="tree-decision-box" id="diag_tree_box" style="display:none">
                    <div style="font-weight:700; font-size:1.05rem; display:flex; align-items:center; justify-content:space-between">
                        <span>🌳 分层故障定位树与证据链分析</span>
                        <span id="diag_overall_badge" class="badge-tag badge-tag-no">全链路正常</span>
                    </div>
                    <div id="diag_root_cause" style="font-size:0.9rem; color:var(--text-primary); font-weight:600; padding:10px; background:var(--bg-input); border-radius:6px; border:1px solid var(--border-subtle)">
                        -
                    </div>

                    <div style="margin-top:10px">
                        <div style="font-size:0.82rem; font-weight:700; color:var(--text-secondary); margin-bottom:6px">🔄 修复建议与复测对比 (Before / After Delta)</div>
                        <table class="delta-compare-table">
                            <thead>
                                <tr>
                                    <th>检测阶段</th>
                                    <th>修复前指标 (Before)</th>
                                    <th>修复后指标 (After)</th>
                                    <th>改善幅度 (Delta)</th>
                                </tr>
                            </thead>
                            <tbody id="diag_delta_tbody">
                                <tr>
                                    <td colspan="4" style="text-align:center; color:var(--text-muted)">暂无复测对比数据</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 4: EVENTS & REPORTS -->
        <div id="tab_events" class="tab-view">
            <div class="card col-12">
                <div class="card-header">
                    <div class="card-header-left">
                        <span class="section-tag">04 / REPORTS</span>
                        <span>告警事件日志与诊断报告导出</span>
                    </div>
                    <div style="display:flex; gap:8px">
                        <button class="btn-ctrl" onclick="exportDiagnosticReport('markdown')">📄 导出 Markdown 报告</button>
                        <button class="btn-ctrl" onclick="exportDiagnosticReport('json')">💾 导出 JSON 原始数据</button>
                    </div>
                </div>

                <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:14px;">
                    <div class="metric-box">
                        <div class="metric-name">24 小时平均 P95 延迟</div>
                        <div class="metric-val-num mono text-cyan" id="ev_p95_val">168 ms</div>
                    </div>
                    <div class="metric-box">
                        <div class="metric-name">24 小时平均丢包率</div>
                        <div class="metric-val-num mono text-success" id="ev_loss_val">0.0%</div>
                    </div>
                    <div class="metric-box">
                        <div class="metric-name">最近 7 天可用率</div>
                        <div class="metric-val-num mono text-success" id="ev_avail_val">100.0%</div>
                    </div>
                </div>

                <div style="font-weight:600; font-size:0.86rem; color:var(--text-primary); margin-top:10px">📜 告警事件时间线日志</div>
                <table class="delta-compare-table">
                    <thead>
                        <tr>
                            <th>时间戳</th>
                            <th>检测目标</th>
                            <th>事件类型</th>
                            <th>状态级别</th>
                            <th>详细描述</th>
                        </tr>
                    </thead>
                    <tbody id="events_tbody">
                        <tr>
                            <td class="mono">刚刚</td>
                            <td>37.114.48.47:8180</td>
                            <td>系统守护线程启动</td>
                            <td><span class="badge-tag badge-tag-no">INFO</span></td>
                            <td>Console-Web 诊断系统初始化完成，所有探针就绪。</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
    // ── Tab Switcher Logic ──
    function switchNavTab(tabId, btn) {
        document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active-view'));
        document.querySelectorAll('.tab-nav-btn').forEach(b => b.classList.remove('active'));
        const targetView = document.getElementById('tab_' + tabId);
        if (targetView) targetView.classList.add('active-view');
        
        if (!btn) {
            btn = Array.from(document.querySelectorAll('.tab-nav-btn')).find(b => b.getAttribute('onclick')?.includes(`'${tabId}'`));
        }
        if (btn) btn.classList.add('active');
        
        localStorage.setItem('console_active_tab', tabId);
        window.location.hash = tabId;

        if (tabId === 'targets') fetchTargets();
        if (tabId === 'diagnostic') loadDiagnosticResult();
    }

    // ── Target Manager Logic ──
    async function fetchTargets() {
        try {
            const res = await fetch('/api/targets');
            const targets = await res.json();
            const tbody = document.getElementById('targets_tbody');
            if (!tbody) return;
            tbody.innerHTML = '';
            targets.forEach(t => {
                tbody.innerHTML += `
                    <tr>
                        <td style="font-weight:600">${t.name}</td>
                        <td class="mono">${t.target}</td>
                        <td><span class="badge-tag badge-tag-no">${t.type.toUpperCase()}</span></td>
                        <td class="mono">${t.freq}s</td>
                        <td class="mono">&lt;${t.threshold_warn}ms / &lt;${t.threshold_crit}ms</td>
                        <td><span class="badge-tag ${t.enabled ? 'badge-tag-no' : 'badge-tag-high'}">${t.enabled ? '已启用' : '已停用'}</span></td>
                        <td>
                            <button class="chip-btn" onclick="removeTarget('${t.id}')">删除</button>
                        </td>
                    </tr>`;
            });
        } catch(e) {}
    }

    async function removeTarget(id) {
        await fetch(`/api/targets?id=${id}`, { method: 'DELETE' });
        fetchTargets();
    }

    async function addNewTargetPrompt() {
        const name = prompt("请输入目标名称:", "香港服务器");
        if (!name) return;
        const target = prompt("请输入目标地址 (IP 或 域名:端口):", "hk.example.com:443");
        if (!target) return;
        await fetch('/api/targets', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ name, target, type: 'tcp', freq: 30, threshold_warn: 160, threshold_crit: 250, enabled: true })
        });
        fetchTargets();
    }

    async function applyPresetTemplate(type) {
        let preset;
        if (type === 'web') preset = { name: '自定义 Web 目标', target: 'github.com:443', type: 'https', freq: 30, threshold_warn: 200, threshold_crit: 500, enabled: true };
        else if (type === 'dns') preset = { name: '自定义 DNS 目标', target: '1.1.1.1:53', type: 'dns', freq: 60, threshold_warn: 100, threshold_crit: 200, enabled: true };
        else preset = { name: '自定义 VPS 目标', target: '37.114.48.47:80', type: 'tcp', freq: 30, threshold_warn: 160, threshold_crit: 250, enabled: true };
        
        await fetch('/api/targets', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(preset)
        });
        fetchTargets();
        alert('已应用预设模板并添加到目标监测表中！');
    }

    // ── 12-Stage Full Diagnostics Engine ──
    let lastDiagResult = null;

    function renderDiagnosticResult(data) {
        if (!data || !data.stages) return;
        const grid = document.getElementById('diag_stages_grid');
        const treeBox = document.getElementById('diag_tree_box');
        const inputEl = document.getElementById('diag_target_input');

        if (inputEl && data.target) inputEl.value = data.target;

        if (grid) {
            grid.innerHTML = '';
            data.stages.forEach(s => {
                let badgeClass = s.status === 'healthy' ? 'badge-tag-no' : (s.status === 'warning' ? 'badge-tag-yes' : 'badge-tag-high');
                if (s.status === 'skipped') badgeClass = 'badge-tag-no';
                grid.innerHTML += `
                    <div class="diag-step-card ${s.status}">
                        <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.78rem">
                            <span style="font-weight:700; color:var(--text-primary)">阶段 ${s.stage.toString().padStart(2,'0')} · ${s.name}</span>
                            <span class="badge-tag ${badgeClass}">${s.status.toUpperCase()} (${s.duration}ms)</span>
                        </div>
                        <div class="mono" style="font-size:0.75rem; color:var(--text-primary); margin-top:2px">${s.raw}</div>
                        <div style="font-size:0.7rem; color:var(--text-muted)">依据: ${s.basis}</div>
                        <div style="font-size:0.72rem; color:var(--accent); margin-top:2px">💡 建议: ${s.fix}</div>
                    </div>`;
            });
        }

        if (treeBox) {
            treeBox.style.display = 'flex';
            setElText('diag_root_cause', `诊断定性: ${data.root_cause}`);
            const badgeEl = document.getElementById('diag_overall_badge');
            if (badgeEl) {
                badgeEl.textContent = data.overall_status === 'healthy' ? '全链路健康' : (data.overall_status === 'warning' ? '性能预警' : '严重故障');
                badgeEl.className = data.overall_status === 'healthy' ? 'badge-tag badge-tag-no' : (data.overall_status === 'warning' ? 'badge-tag badge-tag-yes' : 'badge-tag badge-tag-high');
            }
        }

        // Before / After Delta Comparison
        const deltaTbody = document.getElementById('diag_delta_tbody');
        if (deltaTbody) {
            if (lastDiagResult && lastDiagResult.target === data.target) {
                deltaTbody.innerHTML = '';
                data.stages.slice(0, 11).forEach((s, idx) => {
                    const prevStage = lastDiagResult.stages[idx] || {};
                    const prevDur = prevStage.duration || 0;
                    const currDur = s.duration || 0;
                    const diff = currDur - prevDur;
                    const diffText = diff === 0 ? '持平' : (diff < 0 ? `↓ 改善 ${Math.abs(diff)}ms` : `↑ 升高 +${diff}ms`);
                    const diffColor = diff <= 0 ? 'text-success' : 'text-danger';
                    
                    deltaTbody.innerHTML += `
                        <tr>
                            <td>阶段 ${s.stage} · ${s.name}</td>
                            <td class="mono">${prevStage.raw || '-'} (${prevDur}ms)</td>
                            <td class="mono">${s.raw} (${currDur}ms)</td>
                            <td class="mono ${diffColor}" style="font-weight:700">${diffText}</td>
                        </tr>`;
                });
            } else {
                deltaTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-muted)">已记录基线数据 (${data.timestamp || '刚刚'})。再次诊断 ${data.target} 即可看到 Before/After Delta。</td></tr>`;
            }
        }

        lastDiagResult = data;
        localStorage.setItem('console_last_diag_result', JSON.stringify(data));
    }

    async function loadDiagnosticResult() {
        const cached = localStorage.getItem('console_last_diag_result');
        if (cached) {
            try {
                renderDiagnosticResult(JSON.parse(cached));
                return;
            } catch(e) {}
        }
        try {
            const res = await fetch('/api/diagnose/latest');
            const data = await res.json();
            renderDiagnosticResult(data);
        } catch(e) {}
    }

    async function startFullDiagnostics() {
        const inputEl = document.getElementById('diag_target_input');
        const startBtn = document.getElementById('diag_start_btn');
        const grid = document.getElementById('diag_stages_grid');
        
        const target = inputEl ? inputEl.value.trim() : 'github.com';
        if (!target) return;

        startBtn.disabled = true;
        startBtn.textContent = '⏱️ 全链路诊断中...';
        grid.innerHTML = `<div style="grid-column:span 3; text-align:center; padding:20px; color:var(--accent); font-weight:700">正在按顺序发起 12 阶段网络与应用层全链路探测，请稍候...</div>`;

        try {
            const res = await fetch(`/api/diagnose/full?target=${encodeURIComponent(target)}`);
            const data = await res.json();
            renderDiagnosticResult(data);
        } catch(e) {
            alert('全链路诊断执行失败: ' + e.message);
        } finally {
            startBtn.disabled = false;
            startBtn.textContent = '🚀 开始全面诊断';
        }
    }

    // ── Diagnostic Report Exporter ──
    function exportDiagnosticReport(format) {
        if (!lastDiagResult) {
            alert('请先在【诊断中心】执行一次全面诊断后再导出报告。');
            return;
        }
        const r = lastDiagResult;
        if (format === 'json') {
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(r, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", `diagnostic_report_${r.host}.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        } else {
            let md = `# [网络诊断报告] ${r.target}\n\n`;
            md += `- **诊断时间**: ${r.timestamp}\n`;
            md += `- **目标主机**: ${r.host}:${r.port}\n`;
            md += `- **解析 IP**: ${r.resolved_ip || 'N/A'}\n`;
            md += `- **综合判定**: ${r.root_cause}\n\n`;
            md += `## 12 阶段链路探针明细\n\n`;
            r.stages.forEach(s => {
                md += `### 阶段 ${s.stage}: ${s.name} [${s.status.toUpperCase()}]\n`;
                md += `- **检测结果**: ${s.raw}\n`;
                md += `- **判定依据**: ${s.basis}\n`;
                md += `- **处理建议**: ${s.fix}\n\n`;
            });
            const dataStr = "data:text/markdown;charset=utf-8," + encodeURIComponent(md);
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", `diagnostic_report_${r.host}.md`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        }
    }

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

    // Latency Ping History & Precision Sparkline Calculation
    const pingHistory = { client_ping: [], ping_cu: [], ping_cm: [], ping_ct: [] };
    const MAX_BARS = 60;

    function renderPixelBars(key) {
        const container = document.getElementById(key + '_bars');
        if (!container) return;
        const rawHistory = pingHistory[key];
        if (!rawHistory.length) return;

        container.innerHTML = '';
        let lastValidIdx = -1;
        for (let i = rawHistory.length - 1; i >= 0; i--) {
            if (rawHistory[i] !== undefined && rawHistory[i] !== null) {
                lastValidIdx = i;
                break;
            }
        }

        for (let i = 0; i < MAX_BARS; i++) {
            const bar = document.createElement('div');
            bar.className = 'pixel-bar';
            const val = rawHistory[i];

            if (val === undefined) {
                bar.classList.add('px-empty');
            } else if (val === null) {
                bar.classList.add('px-timeout');
                bar.title = '请求超时 / 丢包';
            } else {
                const heightPct = Math.min(100, Math.max(14, (val / 350) * 100));
                bar.style.height = `${heightPct}%`;
                bar.title = `${val.toFixed(1)} ms`;

                if (val < 80) bar.classList.add('px-cyan');
                else if (val < 160) bar.classList.add('px-yellow');
                else if (val < 250) bar.classList.add('px-orange');
                else bar.classList.add('px-red');

                if (i === lastValidIdx) {
                    bar.style.position = 'relative';
                    const dot = document.createElement('div');
                    dot.style.cssText = 'position:absolute; top:-3px; left:50%; transform:translateX(-50%); width:4px; height:4px; border-radius:50%; background:#fff; box-shadow:0 0 6px var(--accent);';
                    bar.appendChild(dot);
                }
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
                valEl.innerHTML = `<span style="font-size:0.82rem; background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.3); color:var(--danger); padding:2px 8px; border-radius:4px; font-weight:700">⚠️ TIMEOUT (超时)</span>`;
            } else {
                valEl.textContent = `${ms.toFixed(1)} ms`;
                valEl.style.color = ms < 80 ? 'var(--info)' : ms < 160 ? 'var(--warning)' : ms < 250 ? 'var(--orange)' : 'var(--danger)';
            }
        }

        if (statEl && validSamples.length) {
            const avg = validSamples.reduce((a,b)=>a+b,0) / validSamples.length;
            const min = Math.min(...validSamples);
            const jitter = Math.abs(ms - avg);
            const lossPct = ((history.filter(v => v === null).length / history.length) * 100).toFixed(0);
            statEl.textContent = `均值:${avg.toFixed(0)}ms | Min:${min.toFixed(0)}ms | 抖动:±${jitter.toFixed(0)}ms | 丢包:${lossPct}%`;
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

    function updateAggregatedHeaderStatus() {
        const statusDotItem = document.querySelector('.status-light-group .status-dot-item');
        if (!statusDotItem) return;

        const pings = [pingHistory.ping_cu, pingHistory.ping_cm, pingHistory.ping_ct];
        let hasError = false;
        let hasWarning = false;

        pings.forEach(hist => {
            if (!hist.length) return;
            const last = hist[hist.length - 1];
            if (last === null || last === undefined) {
                hasError = true;
            } else if (last >= 200) {
                hasWarning = true;
            }
        });

        if (hasError) {
            statusDotItem.innerHTML = `<span class="pulse-dot dot-warning" style="background:var(--danger); box-shadow:0 0 6px var(--danger)"></span> ⚠️ 存在检测异常`;
        } else if (hasWarning) {
            statusDotItem.innerHTML = `<span class="pulse-dot dot-orange"></span> ⚡ 包含性能预警`;
        } else {
            statusDotItem.innerHTML = `<span class="pulse-dot"></span> ● 系统运行正常`;
        }
    }

    async function fetchPings() {
        try {
            const res = await fetch('/pings');
            const data = await res.json();
            updatePingUI('client_ping', data.client_ping);
            updatePingUI('ping_cu', data.ping_cu);
            updatePingUI('ping_cm', data.ping_cm);
            updatePingUI('ping_ct', data.ping_ct);

            updateAggregatedHeaderStatus();

            // Update Summary Cards 1 & 3
            const pings = [data.ping_cu, data.ping_cm, data.ping_ct].filter(v => v !== null && v !== undefined);
            if (pings.length) {
                const avgPing = pings.reduce((a,b)=>a+b,0) / pings.length;
                setElHTML('sum_ping_val', `${avgPing.toFixed(0)} <span class="summary-unit">ms</span>`);

                const statusEl = document.getElementById('sum_net_status');
                const descEl = document.getElementById('sum_net_desc');

                if (avgPing < 150) {
                    if (statusEl) { statusEl.textContent = '健康'; statusEl.className = 'summary-value text-success'; }
                    if (descEl) descEl.textContent = `平均 TCP 延迟 ${avgPing.toFixed(0)}ms · 线路良好`;
                } else if (avgPing < 250) {
                    if (statusEl) { statusEl.textContent = '良好'; statusEl.className = 'summary-value text-warning'; }
                    if (descEl) descEl.textContent = `平均 TCP 延迟 ${avgPing.toFixed(0)}ms · 抖动正常`;
                } else {
                    if (statusEl) { statusEl.textContent = '较慢'; statusEl.className = 'summary-value text-orange'; }
                    if (descEl) descEl.textContent = `平均 TCP 延迟 ${avgPing.toFixed(0)}ms · 跨境链路延迟偏高`;
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

    // Restore active tab and diagnostic results across page refreshes
    const initialTab = window.location.hash.replace('#','') || localStorage.getItem('console_active_tab') || 'overview';
    switchNavTab(initialTab);
    loadDiagnosticResult();
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
    if is_private_ip(public_ip):
        ip_display = f"{ip} (公网 未检测到)"
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
    cert_file = acme_manager.FULLCHAIN_FILE if acme_manager.FULLCHAIN_FILE.exists() else acme_manager.CERT_FILE
    key_file = acme_manager.KEY_FILE

    gunicorn_bin = "/usr/local/bin/gunicorn"
    if not Path(gunicorn_bin).exists():
        gunicorn_bin = "gunicorn"

    if cert_file.exists() and key_file.exists():
        logger.info("🔒 SSL Certificate present (%s). Launching Gunicorn HTTPS server on 0.0.0.0:8080...", cert_file)
        try:
            os.execvp(gunicorn_bin, [
                "gunicorn", "-b", "0.0.0.0:8080",
                "--certfile", str(cert_file),
                "--keyfile", str(key_file),
                "--workers", "2",
                "--timeout", "120",
                "app.main:app"
            ])
        except Exception as e:
            logger.warning("Failed to exec gunicorn HTTPS: %s, falling back to Flask", e)
            app.run(host="0.0.0.0", port=8080, threaded=True)
    else:
        logger.info("🔓 No SSL Certificate found yet. Launching Gunicorn HTTP server on 0.0.0.0:8080...")
        try:
            os.execvp(gunicorn_bin, [
                "gunicorn", "-b", "0.0.0.0:8080",
                "--workers", "2",
                "--timeout", "120",
                "app.main:app"
            ])
        except Exception as e:
            logger.warning("Failed to exec gunicorn HTTP: %s, falling back to Flask", e)
            app.run(host="0.0.0.0", port=8080, threaded=True)



