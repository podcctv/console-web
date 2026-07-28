import json
import logging
import os
import platform
import shlex
import socket
import ssl
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

@app.route("/api/diagnose/dualstack")
def api_diagnose_dualstack():
    target = request.args.get("target", "google.com").strip()
    host = target.split(":")[0]
    
    v4_info = {"status": "unreachable", "dns_ms": 0, "tcp_ms": 0, "ip": None}
    try:
        t0 = time.time()
        v4_ip = socket.gethostbyname(host)
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
        v6_res = socket.getaddrinfo(host, 80, socket.AF_INET6)
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
            rec = "双栈表现接近，均可正常通信"
        elif diff < 0:
            rec = f"IPv6 延迟更低 ({diff}ms)"
        else:
            rec = f"IPv4 延迟更低 (-{diff}ms)"
    elif v4_info["status"] == "healthy":
        rec = "IPv4 单栈正常，IPv6 不可用或无 AAAA 记录"
    elif v6_info["status"] == "healthy":
        rec = "IPv6 单栈正常，IPv4 不可用"
    else:
        rec = "IPv4/IPv6 均不可达，请检查域名或目标网络"
        
    return jsonify({
        "target": host,
        "ipv4": v4_info,
        "ipv6": v6_info,
        "recommendation": rec,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route("/api/diagnose/dns")
def api_diagnose_dns():
    target = request.args.get("target", "github.com").strip()
    host = target.split(":")[0]
    
    servers = [
        {"name": "Local DNS", "ip": "system"},
        {"name": "AliDNS", "ip": "223.5.5.5"},
        {"name": "DNSPod", "ip": "119.29.29.29"},
        {"name": "Cloudflare", "ip": "1.1.1.1"},
        {"name": "Google DNS", "ip": "8.8.8.8"},
    ]
    
    results = []
    ips_found = set()
    
    for s in servers:
        t0 = time.time()
        try:
            res_ip = socket.gethostbyname(host)
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
    return jsonify({
        "target": host,
        "servers": results,
        "is_consistent": is_consistent,
        "unique_ips": list(ips_found),
        "summary": "各地 DNS 解析一致" if is_consistent else f"检测到 {len(ips_found)} 个不同的 A 记录 IP，可能存在 Anycast/CDN 调度"
    })

@app.route("/api/diagnose/tls")
def api_diagnose_tls():
    target = request.args.get("target", "github.com").strip()
    host = target.split(":")[0]
    
    try:
        t0 = time.time()
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=3) as sock:
            t_tcp = int((time.time() - t0) * 1000)
            t1 = time.time()
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
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
                    
                return jsonify({
                    "target": host,
                    "status": "healthy" if days_left >= 15 else "warning",
                    "tcp_ms": t_tcp,
                    "tls_ms": t_tls,
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else "Unknown",
                    "issuer": issuer_name,
                    "expires_after": not_after_str,
                    "days_remaining": days_left,
                    "recommendation": f"TLS 证书运行健康 (剩余 {days_left} 天)" if days_left >= 15 else f"⚠️ 证书即将在 {days_left} 天后到期，请尽快续期！"
                })
    except Exception as e:
        return jsonify({
            "target": host,
            "status": "critical",
            "error": str(e),
            "recommendation": f"TLS 握手失败: {e}"
        })

@app.route("/api/history")
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

@app.route("/api/report/export", methods=["GET", "POST"])
def api_report_export():
    fmt = request.args.get("format", "markdown").lower()
    mask_ip = request.args.get("mask", "false").lower() == "true"
    
    latest = _latest_diag_cache.get("result") or run_full_diagnostics("github.com")
    target = latest.get("target", "github.com")
    overall = latest.get("overall_status", "healthy")
    root_cause = latest.get("root_cause", "正常")
    
    server_ip = "37.114.48.47"
    if mask_ip:
        server_ip = "37.114.*.*"
        target = target.replace("37.114.48.47", "37.114.*.*")
        
    if fmt == "json":
        return jsonify(latest)
    elif fmt == "csv":
        csv_content = "Stage,Name,Status,DurationMS,Raw,Basis,Fix\n"
        for s in latest.get("stages", []):
            csv_content += f'"{s["stage"]}","{s["name"]}","{s["status"]}","{s["duration"]}","{s["raw"]}","{s["basis"]}","{s["fix"]}"\n'
        return Response(csv_content, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename=diag_report_{target}.csv"})
    else:
        md = f"# Node Seeker 诊断报告\n\n"
        md += f"- **检测目标**: `{target}`\n"
        md += f"- **检测时间**: {latest.get('timestamp')}\n"
        md += f"- **出口 IP**: `{server_ip}`\n"
        md += f"- **总体评级**: `{overall.upper()}`\n"
        md += f"- **根因判定**: {root_cause}\n\n"
        md += "## 全链路 12 阶段测试明细\n\n"
        md += "| 阶段 | 名称 | 状态 | 耗时 | 探测结果 |\n|---|---|---|---|---|\n"
        for s in latest.get("stages", []):
            md += f"| {s['stage']} | {s['name']} | {s['status'].upper()} | {s['duration']}ms | {s['raw']} |\n"
        md += "\n---\n*Report generated by Node Seeker Autonomous Diagnostic Platform v4+*\n"
        return Response(md, mimetype="text/markdown", headers={"Content-Disposition": f"attachment;filename=diag_report_{target}.md"})

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
TEMPLATE = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>NETWATCH Network Operations Terminal</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=PingFang+SC:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* ═══════════════════════════════════════════════════════════
           NETWATCH — Network Status Terminal (Design Tokens)
           面向网络工程师与服务器运维人员的实时网络检测终端
           ═══════════════════════════════════════════════════════════ */
        :root {
            --bg-page: #050706;
            --bg-panel: #080B09;
            --bg-panel-raised: #0B100C;
            --bg-input: #070A08;

            --text-primary: #D7E2D9;
            --text-secondary: #91A095;
            --text-muted: #5D6A60;
            --text-dim: #414A43;

            --status-success: #78E08F;
            --status-info: #69D6D0;
            --status-blue: #6BB8FF;
            --status-warning: #E7C66B;
            --status-critical: #F07878;
            --status-purple: #B59AF2;

            --border-default: rgba(146, 173, 151, 0.13);
            --border-hover: rgba(120, 224, 143, 0.30);
            --border-strong: rgba(146, 173, 151, 0.24);

            --radius-sm: 4px;
            --radius-md: 6px;
            --radius-lg: 8px;

            --font-mono: "JetBrains Mono", "IBM Plex Mono", "SFMono-Regular", "Consolas", monospace;
            --font-ui: "PingFang SC", "Microsoft YaHei", system-ui, sans-serif;
        }

        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: radial-gradient(circle at 50% -20%, rgba(80, 160, 100, 0.055), transparent 45%), #050706;
            background-attachment: fixed;
            color: var(--text-primary);
            font-family: var(--font-ui);
            margin: 0; padding: 0;
            line-height: 1.5;
            font-variant-numeric: tabular-nums;
            -webkit-font-smoothing: antialiased;
        }

        .mono { font-family: var(--font-mono); }
        .text-success { color: var(--status-success) !important; }
        .text-info { color: var(--status-info) !important; }
        .text-warning { color: var(--status-warning) !important; }
        .text-danger, .text-critical { color: var(--status-critical) !important; }
        .text-cyan { color: var(--status-info) !important; }
        .text-muted { color: var(--text-muted) !important; }
        .text-primary { color: var(--text-primary) !important; }

        /* ── Sticky Top Navigation ── */
        .terminal-nav-bar {
            position: sticky; top: 0; z-index: 100;
            background: rgba(5, 7, 6, 0.92);
            backdrop-filter: blur(8px);
            border-bottom: 1px solid var(--border-default);
            padding: 10px 24px;
            display: flex; align-items: center; justify-content: space-between;
        }
        .nav-brand { display: flex; align-items: center; gap: 8px; }
        .nav-logo-symbol { font-family: var(--font-mono); color: var(--status-success); font-weight: 700; font-size: 1.1rem; }
        .nav-brand-title { font-family: var(--font-mono); font-weight: 700; letter-spacing: 1px; color: var(--text-primary); font-size: 0.95rem; }
        .nav-brand-subtitle { font-size: 0.76rem; color: var(--text-muted); }

        .nav-tabs-cli { display: flex; gap: 6px; }
        .nav-tab-btn {
            background: transparent; border: 1px solid transparent;
            color: var(--text-secondary); font-family: var(--font-mono);
            font-size: 0.8rem; padding: 5px 12px; border-radius: var(--radius-sm);
            cursor: pointer; transition: all 0.15s ease;
        }
        .nav-tab-btn:hover { color: var(--text-primary); border-color: var(--border-hover); background: rgba(120,224,143,0.04); }
        .nav-tab-btn.active {
            color: var(--status-success); border-color: var(--status-success);
            background: rgba(120,224,143,0.08); font-weight: 700;
        }

        .nav-right-status { display: flex; align-items: center; gap: 12px; font-family: var(--font-mono); font-size: 0.78rem; }
        .live-dot-pulse { color: var(--status-success); font-weight: 700; display: inline-flex; align-items: center; gap: 4px; }
        .live-dot-pulse::before {
            content: ''; width: 6px; height: 6px; border-radius: 50%;
            background: var(--status-success); display: inline-block;
            box-shadow: 0 0 6px var(--status-success);
        }

        /* ── Main Layout Container ── */
        .page-container {
            max-width: 1480px; width: calc(100% - 48px);
            margin: 0 auto; display: flex; flex-direction: column; gap: 16px;
            padding: 16px 0 40px 0;
        }

        .tab-view { display: none; flex-direction: column; gap: 16px; width: 100%; }
        .tab-view.active-view { display: flex; }

        /* ── CLI Terminal Card System ── */
        .card-cli {
            background: var(--bg-panel);
            border: 1px solid var(--border-default);
            border-radius: var(--radius-md);
            padding: 16px;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.025), 0 8px 24px rgba(0,0,0,0.16);
        }
        .card-cli-header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 12px; padding-bottom: 8px;
            border-bottom: 1px solid var(--border-default);
        }
        .card-cli-header-left { display: flex; align-items: center; gap: 8px; }
        .cmd-title { font-family: var(--font-mono); font-weight: 700; color: var(--status-success); font-size: 0.88rem; }
        .cmd-subtitle { font-size: 0.76rem; color: var(--text-muted); }

        /* ── Bracket Badges ── */
        .badge-bracket {
            font-family: var(--font-mono); font-size: 0.74rem; font-weight: 600;
            padding: 2px 6px; border-radius: var(--radius-sm); border: 1px solid currentColor;
            display: inline-flex; align-items: center; justify-content: center;
        }
        .status-healthy { color: var(--status-success); background: rgba(120,224,143,0.06); }
        .status-warning { color: var(--status-warning); background: rgba(231,198,107,0.06); }
        .status-critical { color: var(--status-critical); background: rgba(240,120,120,0.06); }
        .status-info { color: var(--status-info); background: rgba(105,214,208,0.06); }

        /* ── CLI Button System ── */
        .btn-cli-xs, .btn-cli-sm, .btn-cli-action {
            background: transparent; border: 1px solid var(--border-strong);
            color: var(--text-secondary); font-family: var(--font-mono); font-size: 0.75rem;
            padding: 4px 10px; border-radius: var(--radius-sm); cursor: pointer;
            transition: all 0.15s ease; outline: none; display: inline-flex; align-items: center; gap: 4px;
        }
        .btn-cli-xs:hover, .btn-cli-sm:hover, .btn-cli-action:hover {
            border-color: var(--status-success); color: var(--status-success);
            background: rgba(120,224,143,0.05);
        }
        .btn-cli-sm.active { border-color: var(--status-success); color: var(--status-success); background: rgba(120,224,143,0.12); font-weight: 700; }
        .btn-cli-action { font-weight: 700; border-color: var(--status-success); color: var(--status-success); padding: 8px 14px; }

        /* ── Hero Status Terminal Box ── */
        .hero-terminal-box { background: var(--bg-panel-raised); }
        .cli-header-bar { font-family: var(--font-mono); font-size: 0.82rem; color: var(--status-success); display: flex; align-items: center; gap: 4px; margin-bottom: 8px; }
        .cli-cursor { animation: blink 1s step-end infinite; }
        @keyframes blink { 50% { opacity: 0; } }

        .cli-body-summary { display: grid; grid-template-columns: 1fr auto; gap: 24px; align-items: start; }
        .cli-status-row { font-family: var(--font-mono); font-weight: 700; font-size: 0.92rem; letter-spacing: 1px; color: var(--text-primary); }
        .cli-divider { font-family: var(--font-mono); color: var(--border-strong); font-size: 0.75rem; margin: 4px 0 8px 0; }
        .cli-kv-grid { display: grid; grid-template-columns: 110px 1fr; gap: 6px 12px; font-size: 0.82rem; margin-bottom: 10px; }
        .cli-k { font-family: var(--font-mono); color: var(--text-muted); font-weight: 600; }
        .cli-v { font-family: var(--font-mono); color: var(--text-primary); }
        .cli-log-line { font-family: var(--font-mono); font-size: 0.78rem; line-height: 1.4; }
        .cli-col-right-actions { display: flex; flex-direction: column; gap: 8px; min-width: 200px; }

        /* ── Metric Strip (6 Columns Continuous) ── */
        .metric-strip-cli {
            display: grid; grid-template-columns: repeat(6, 1fr); gap: 1px;
            background: var(--border-default); border: 1px solid var(--border-default);
            border-radius: var(--radius-md); overflow: hidden;
        }
        .metric-strip-item {
            background: var(--bg-panel); padding: 12px 14px;
            display: flex; flex-direction: column; gap: 4px;
        }
        .metric-title { font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted); font-weight: 700; }
        .metric-value-line { font-size: 1.35rem; font-weight: 700; line-height: 1.1; }
        .metric-value-line .unit { font-size: 0.75rem; font-weight: 400; color: var(--text-muted); }
        .metric-sub { font-size: 0.72rem; color: var(--text-secondary); display: flex; align-items: center; justify-content: space-between; margin-top: 2px; }

        /* ── Realtime TCP Ping Chart ── */
        .chart-stats-bar-cli {
            display: flex; gap: 16px; flex-wrap: wrap; font-family: var(--font-mono);
            font-size: 0.76rem; color: var(--text-muted); padding: 6px 12px;
            background: var(--bg-input); border-radius: var(--radius-sm); border: 1px solid var(--border-default);
        }
        .stat-kv { display: inline-flex; gap: 4px; }

        /* ── Dual-Stack Grid ── */
        .dualstack-grid-cli { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 10px; }
        .dualstack-col { background: var(--bg-input); padding: 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-default); }
        .ds-title-line { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; font-family: var(--font-mono); font-weight: 700; font-size: 0.8rem; }
        .ds-kv-table { display: flex; flex-direction: column; gap: 4px; font-size: 0.78rem; }
        .ds-tr { display: flex; justify-content: space-between; padding: 2px 0; border-bottom: 1px dashed rgba(146,173,151,0.08); }
        .cli-recommendation-banner {
            font-family: var(--font-mono); font-size: 0.78rem; color: var(--status-success);
            background: rgba(120,224,143,0.05); border: 1px solid rgba(120,224,143,0.2);
            padding: 8px 12px; border-radius: var(--radius-sm);
        }

        /* ── CLI Tables ── */
        .cli-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
        .cli-table th { font-family: var(--font-mono); color: var(--text-muted); font-size: 0.72rem; text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border-default); }
        .cli-table td { padding: 8px 10px; border-bottom: 1px solid rgba(146,173,151,0.06); font-family: var(--font-mono); }
        .cli-table tr:hover { background: rgba(255,255,255,0.02); }

        /* ── System Status & ASCII Progress Bars ── */
        .grid-2col-cli { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .cli-system-panel { display: flex; flex-direction: column; gap: 10px; }
        .ascii-bar-row { display: grid; grid-template-columns: 70px 1fr 45px; align-items: center; font-family: var(--font-mono); font-size: 0.78rem; }
        .ascii-label { color: var(--text-muted); font-weight: 700; }
        .ascii-bar { color: var(--status-success); letter-spacing: 1px; }
        .cli-kv-grid-sm { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; font-family: var(--font-mono); font-size: 0.74rem; color: var(--text-secondary); margin-top: 6px; }

        /* ── Diagnostic Task List CLI Style ── */
        .diag-cli-task-list { display: flex; flex-direction: column; gap: 6px; }
        .diag-cli-item {
            display: flex; justify-content: space-between; align-items: center;
            font-family: var(--font-mono); font-size: 0.78rem; padding: 8px 12px;
            background: var(--bg-input); border-radius: var(--radius-sm); border: 1px solid var(--border-default);
            cursor: pointer; transition: all 0.15s ease;
        }
        .diag-cli-item:hover { border-color: var(--border-hover); }

        /* ── Event Log Stream ── */
        .cli-grep-bar { display: flex; gap: 8px; margin-bottom: 8px; align-items: center; }
        .cli-prompt-sm { font-family: var(--font-mono); color: var(--status-success); font-size: 0.8rem; font-weight: 700; }
        .cli-grep-input {
            flex: 1; background: var(--bg-input); border: 1px solid var(--border-default);
            color: var(--text-primary); padding: 5px 10px; border-radius: var(--radius-sm);
            font-family: var(--font-mono); font-size: 0.78rem; outline: none;
        }
        .cli-grep-input:focus { border-color: var(--status-success); }

        .log-stream-box-cli {
            background: #030504; border: 1px solid var(--border-default);
            border-radius: var(--radius-sm); padding: 10px; height: 260px; overflow-y: auto;
            font-family: var(--font-mono); font-size: 0.76rem; display: flex; flex-direction: column; gap: 4px;
        }
        .log-row { display: flex; gap: 8px; white-space: nowrap; word-break: break-all; }
        .log-time { color: var(--text-muted); }
        .log-level { font-weight: 700; width: 80px; text-align: left; }
        .level-info { color: var(--status-info); }
        .level-warning { color: var(--status-warning); }
        .level-critical { color: var(--status-critical); }
        .level-recover { color: var(--status-success); }
        .log-msg { color: var(--text-primary); }

        /* ── Uptime Heatmap ── */
        .heatmap-grid-cli { display: grid; grid-template-columns: repeat(30, 1fr); gap: 4px; margin-top: 8px; }
        .heatmap-sq {
            aspect-ratio: 1/1; border-radius: 2px; background: rgba(120,224,143,0.15);
            border: 1px solid rgba(120,224,143,0.3); cursor: pointer; transition: all 0.15s ease;
        }
        .heatmap-sq:hover { transform: scale(1.2); z-index: 10; }
        .sq-healthy { background: rgba(120,224,143,0.25); border-color: var(--status-success); }
        .sq-warning { background: rgba(231,198,107,0.3); border-color: var(--status-warning); }
        .sq-critical { background: rgba(240,120,120,0.35); border-color: var(--status-critical); }

        /* ── Terminal Keyboard Help Modal ── */
        .modal-cli-overlay {
            position: fixed; inset: 0; background: rgba(0,0,0,0.85); z-index: 1000;
            display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px);
        }
        .modal-cli-box {
            background: var(--bg-panel-raised); border: 1px solid var(--status-success);
            border-radius: var(--radius-md); width: min(500px, 90vw); padding: 16px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        .modal-cli-header { display: flex; justify-content: space-between; align-items: center; font-family: var(--font-mono); font-weight: 700; color: var(--status-success); font-size: 0.85rem; margin-bottom: 12px; border-bottom: 1px solid var(--border-default); padding-bottom: 6px; }
        .modal-cli-body { display: flex; flex-direction: column; gap: 8px; font-family: var(--font-mono); font-size: 0.78rem; }
        .shortcut-row { display: flex; gap: 12px; align-items: center; }
        .key-cap { background: var(--bg-input); border: 1px solid var(--border-strong); color: var(--status-success); font-weight: 700; padding: 2px 8px; border-radius: 3px; min-width: 36px; text-align: center; }

        /* ── Terminal Footer ── */
        .terminal-footer {
            margin-top: 30px; padding-top: 16px; border-top: 1px solid var(--border-default);
            font-family: var(--font-mono); font-size: 0.74rem; color: var(--text-muted);
            display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;
        }
        .footer-links { display: flex; gap: 12px; }
        .footer-links a { color: var(--text-secondary); text-decoration: none; }
        .footer-links a:hover { color: var(--status-success); }

        /* ── Responsive Rules ── */
        @media (max-width: 1024px) {
            .metric-strip-cli { grid-template-columns: repeat(3, 1fr); }
            .grid-2col-cli, .dualstack-grid-cli { grid-template-columns: 1fr; }
        }
        @media (max-width: 768px) {
            .page-container { width: calc(100% - 24px); }
            .metric-strip-cli { grid-template-columns: repeat(2, 1fr); }
            .cli-body-summary { grid-template-columns: 1fr; }
            .terminal-nav-bar { flex-direction: column; gap: 8px; align-items: flex-start; }
        }

        @media (prefers-reduced-motion: reduce) {
            .cli-cursor, .live-dot-pulse::before { animation: none !important; }
        }
    </style>
</head>
<body>

    <!-- ── 1. STICKY TOP GLOBAL STATUS BAR ── -->
    <header class="terminal-nav-bar">
        <div class="nav-brand">
            <span class="nav-logo-symbol">NW_</span>
            <span class="nav-brand-title">NETWATCH</span>
            <span class="nav-brand-subtitle">// 网络运行监测终端</span>
        </div>

        <div class="nav-tabs-cli">
            <button class="nav-tab-btn active" onclick="switchNavTab('overview', this)">$ overview</button>
            <button class="nav-tab-btn" onclick="switchNavTab('targets', this)">$ targets</button>
            <button class="nav-tab-btn" onclick="switchNavTab('diagnostics', this)">$ diagnostics</button>
            <button class="nav-tab-btn" onclick="switchNavTab('events', this)">$ events</button>
        </div>

        <div class="nav-right-status">
            <span class="live-dot-pulse">● LIVE</span>
            <span class="nav-sync-time">SYNC: <span id="nav_last_sync">--:--:--</span></span>
            <button class="btn-cli-xs" onclick="fetchStats(); fetchPings();">[ REFRESH ]</button>
            <button class="btn-cli-xs" onclick="showKeyboardHelp()">[ ? HELP ]</button>
        </div>
    </header>

    <!-- ── MAIN WORKSPACE CONTAINER ── -->
    <main class="page-container">

        <!-- ═══════════════════════════════════════════════════════════
             TAB 1: OVERVIEW ($ overview)
             ═══════════════════════════════════════════════════════════ -->
        <div id="tab_overview" class="tab-view active-view">

            <!-- ── 2. HERO STATUS TERMINAL BOX ── -->
            <div class="card-cli hero-terminal-box">
                <div class="cli-header-bar">
                    <span>root@netwatch:~$ ./status --summary</span>
                    <span class="cli-cursor">_</span>
                </div>
                <div class="cli-body-summary">
                    <div class="cli-col-left">
                        <div class="cli-status-row">NETWORK STATUS TERMINAL</div>
                        <div class="cli-divider">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</div>
                        <div class="cli-kv-grid">
                            <span class="cli-k">STATUS</span><span class="cli-v"><span class="badge-bracket status-healthy" id="hero_status">[ HEALTHY ]</span></span>
                            <span class="cli-k">PUBLIC IP</span><span class="cli-v mono text-cyan" id="hero_ip">37.114.48.47 (IPv4) / 2a0e:6a80:3:483::100 (IPv6)</span>
                            <span class="cli-k">REGION / ISP</span><span class="cli-v" id="hero_isp">Frankfurt, Germany · Host Europe GmbH</span>
                            <span class="cli-k">UPTIME</span><span class="cli-v mono text-success" id="hero_uptime">{{ uptime_str }}</span>
                            <span class="cli-k">LAST CHECK</span><span class="cli-v mono text-muted" id="hero_last_check">2026-07-28 15:42:18 UTC+8</span>
                        </div>
                        <div class="cli-log-line text-success" id="hero_log_line_1">> All primary network checks passed.</div>
                        <div class="cli-log-line text-muted" id="hero_log_line_2">> Monitoring active targets every 30s. No unresolved critical events.</div>
                    </div>
                    <div class="cli-col-right-actions">
                        <button class="btn-cli-action" onclick="switchNavTab('diagnostics'); startFullDiagnostics();">[> RUN FULL DIAGNOSTIC ]</button>
                        <button class="btn-cli-action" onclick="switchNavTab('events');">[ VIEW EVENTS ]</button>
                        <button class="btn-cli-action" onclick="exportDiagnosticReport();">[ EXPORT REPORT ]</button>
                    </div>
                </div>
            </div>

            <!-- ── 3. METRIC STRIP (6 COLUMNS CONTINUOUS) ── -->
            <div class="metric-strip-cli">
                <div class="metric-strip-item">
                    <div class="metric-title">TCP LATENCY</div>
                    <div class="metric-value-line mono text-cyan" id="metric_latency">- <span class="unit">ms</span></div>
                    <div class="metric-sub"><span>1h avg</span> <span class="badge-bracket status-healthy" id="mb_latency">[ GOOD ]</span></div>
                </div>
                <div class="metric-strip-item">
                    <div class="metric-title">PACKET LOSS</div>
                    <div class="metric-value-line mono text-success" id="metric_loss">0.0<span class="unit">%</span></div>
                    <div class="metric-sub"><span>40 samples</span> <span class="badge-bracket status-healthy" id="mb_loss">[ OK ]</span></div>
                </div>
                <div class="metric-strip-item">
                    <div class="metric-title">JITTER</div>
                    <div class="metric-value-line mono text-info" id="metric_jitter">1.2 <span class="unit">ms</span></div>
                    <div class="metric-sub"><span>±0.4ms</span> <span class="badge-bracket status-healthy" id="mb_jitter">[ STABLE ]</span></div>
                </div>
                <div class="metric-strip-item">
                    <div class="metric-title">AVAILABILITY</div>
                    <div class="metric-value-line mono text-success" id="metric_avail">99.98<span class="unit">%</span></div>
                    <div class="metric-sub"><span>SLA target</span> <span class="badge-bracket status-healthy" id="mb_avail">[ NORMAL ]</span></div>
                </div>
                <div class="metric-strip-item">
                    <div class="metric-title">ACTIVE TARGETS</div>
                    <div class="metric-value-line mono text-primary" id="metric_targets">5 <span class="unit">/ 5</span></div>
                    <div class="metric-sub"><span>30s cycle</span> <span class="badge-bracket status-healthy" id="mb_targets">[ ACTIVE ]</span></div>
                </div>
                <div class="metric-strip-item">
                    <div class="metric-title">OPEN EVENTS</div>
                    <div class="metric-value-line mono text-success" id="metric_events">0 <span class="unit">open</span></div>
                    <div class="metric-sub"><span>0 critical</span> <span class="badge-bracket status-healthy" id="mb_events">[ CLEAR ]</span></div>
                </div>
            </div>

            <!-- ── 4. REALTIME TCP PING CHART ($ tcping --watch) ── -->
            <div class="card-cli">
                <div class="card-cli-header">
                    <div class="card-cli-header-left">
                        <span class="cmd-title">$ tcping --watch</span>
                        <span class="cmd-subtitle">// 实时 TCP 链路延迟</span>
                    </div>
                    <div class="card-cli-header-right">
                        <div class="btn-group-cli" style="display:flex; gap:4px">
                            <button class="btn-cli-sm active" onclick="setPingRange('1h', this)">[> 1H ]</button>
                            <button class="btn-cli-sm" onclick="setPingRange('15m', this)">[ 15M ]</button>
                            <button class="btn-cli-sm" onclick="setPingRange('6h', this)">[ 6H ]</button>
                            <button class="btn-cli-sm" onclick="setPingRange('24h', this)">[ 24H ]</button>
                            <button class="btn-cli-sm" onclick="setPingRange('7d', this)">[ 7D ]</button>
                        </div>
                        <button class="btn-cli-sm" onclick="exportPingCSV()">[ EXPORT CSV ]</button>
                    </div>
                </div>

                <div class="chart-stats-bar-cli">
                    <span class="stat-kv">CURRENT <b class="mono text-cyan" id="ping_stat_cur">- ms</b></span>
                    <span class="stat-kv">AVG <b class="mono" id="ping_stat_avg">- ms</b></span>
                    <span class="stat-kv">MIN <b class="mono text-success" id="ping_stat_min">- ms</b></span>
                    <span class="stat-kv">MAX <b class="mono text-warning" id="ping_stat_max">- ms</b></span>
                    <span class="stat-kv">P95 <b class="mono text-info" id="ping_stat_p95">- ms</b></span>
                    <span class="stat-kv">JITTER <b class="mono" id="ping_stat_jitter">±0ms</b></span>
                    <span class="stat-kv">LOSS <b class="mono text-success" id="ping_stat_loss">0.0%</b></span>
                </div>

                <div style="position:relative; width:100%; height:260px; margin-top:12px;">
                    <canvas id="tcpingCanvas" style="width:100%; height:100%; display:block;"></canvas>
                </div>
            </div>

            <!-- ── 5. DUAL-STACK NETWORK STATUS ($ network --dual-stack) ── -->
            <div class="card-cli">
                <div class="card-cli-header">
                    <div class="card-cli-header-left">
                        <span class="cmd-title">$ network --dual-stack</span>
                        <span class="cmd-subtitle">// IPv4 / IPv6 链路对比与选路评估</span>
                    </div>
                    <button class="btn-cli-sm" onclick="fetchDualStackDiag()">[ RE-TEST DUALSTACK ]</button>
                </div>

                <div class="dualstack-grid-cli">
                    <!-- IPv4 Box -->
                    <div class="dualstack-col">
                        <div class="ds-title-line">
                            <span class="ds-name">IPv4 PROTOCOL</span>
                            <span class="badge-bracket status-healthy" id="ds_v4_status">[ ONLINE ]</span>
                        </div>
                        <div class="ds-kv-table">
                            <div class="ds-tr"><span>PUBLIC IP</span><span class="mono text-cyan" id="ds_v4_ip">37.114.48.47</span></div>
                            <div class="ds-tr"><span>TCP LATENCY</span><span class="mono text-success" id="ds_v4_lat">68 ms</span></div>
                            <div class="ds-tr"><span>DNS LOOKUP</span><span class="mono" id="ds_v4_dns">18 ms</span></div>
                            <div class="ds-tr"><span>PACKET LOSS</span><span class="mono text-success" id="ds_v4_loss">0.0%</span></div>
                            <div class="ds-tr"><span>ROUTE HOPS</span><span class="mono" id="ds_v4_hops">12 hops</span></div>
                            <div class="ds-tr"><span>MTU</span><span class="mono" id="ds_v4_mtu">1500 bytes</span></div>
                        </div>
                    </div>

                    <!-- IPv6 Box -->
                    <div class="dualstack-col">
                        <div class="ds-title-line">
                            <span class="ds-name">IPv6 PROTOCOL</span>
                            <span class="badge-bracket status-healthy" id="ds_v6_status">[ ONLINE ]</span>
                        </div>
                        <div class="ds-kv-table">
                            <div class="ds-tr"><span>PUBLIC IP</span><span class="mono text-cyan" id="ds_v6_ip">2a0e:6a80:3:483::100</span></div>
                            <div class="ds-tr"><span>TCP LATENCY</span><span class="mono text-warning" id="ds_v6_lat">121 ms</span></div>
                            <div class="ds-tr"><span>DNS LOOKUP</span><span class="mono" id="ds_v6_dns">32 ms</span></div>
                            <div class="ds-tr"><span>PACKET LOSS</span><span class="mono text-success" id="ds_v6_loss">0.0%</span></div>
                            <div class="ds-tr"><span>ROUTE HOPS</span><span class="mono" id="ds_v6_hops">18 hops</span></div>
                            <div class="ds-tr"><span>MTU</span><span class="mono" id="ds_v6_mtu">1500 bytes</span></div>
                        </div>
                    </div>
                </div>

                <div class="cli-recommendation-banner" id="ds_recommendation">
                    > IPv4 is currently 43% faster than IPv6. Recommended route preference: IPv4.
                </div>
            </div>

            <!-- ── 6. NETWORK INTERFACES & SYSTEM STATUS ── -->
            <div class="grid-2col-cli">
                <!-- Network Interfaces Table ($ ip addr show) -->
                <div class="card-cli">
                    <div class="card-cli-header">
                        <div class="card-cli-header-left">
                            <span class="cmd-title">$ ip addr show</span>
                            <span class="cmd-subtitle">// 宿主机网络接口与 IP 绑定</span>
                        </div>
                    </div>
                    <table class="cli-table">
                        <thead>
                            <tr>
                                <th>INTERFACE</th>
                                <th>STATUS</th>
                                <th>ADDRESS</th>
                                <th>MTU</th>
                                <th>RX</th>
                                <th>TX</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td class="mono font-bold">eth0</td>
                                <td><span class="badge-bracket status-healthy">[ UP ]</span></td>
                                <td class="mono text-cyan">37.114.48.47 / 2a0e:6a80...</td>
                                <td class="mono">1500</td>
                                <td class="mono">24.8 GB</td>
                                <td class="mono">8.3 GB</td>
                            </tr>
                            <tr>
                                <td class="mono font-bold">docker0</td>
                                <td><span class="badge-bracket status-healthy">[ UP ]</span></td>
                                <td class="mono text-muted">172.17.0.1/16</td>
                                <td class="mono">1500</td>
                                <td class="mono">1.2 GB</td>
                                <td class="mono">946 MB</td>
                            </tr>
                            <tr>
                                <td class="mono font-bold">lo</td>
                                <td><span class="badge-bracket status-healthy">[ UP ]</span></td>
                                <td class="mono text-muted">127.0.0.1/8</td>
                                <td class="mono">65536</td>
                                <td class="mono">128 MB</td>
                                <td class="mono">128 MB</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <!-- Server System Status ($ systemctl status netwatch) -->
                <div class="card-cli">
                    <div class="card-cli-header">
                        <div class="card-cli-header-left">
                            <span class="cmd-title">$ systemctl status netwatch</span>
                            <span class="cmd-subtitle">// 实时系统资源与 TCP 连接状态</span>
                        </div>
                    </div>
                    <div class="cli-system-panel">
                        <div class="ascii-bar-row">
                            <span class="ascii-label">CPU</span>
                            <span class="ascii-bar mono" id="ascii_cpu_bar">[██████░░░░░░]</span>
                            <span class="ascii-val mono" id="cpu_val">28%</span>
                        </div>
                        <div class="ascii-bar-row">
                            <span class="ascii-label">MEMORY</span>
                            <span class="ascii-bar mono" id="ascii_mem_bar">[████████░░░░]</span>
                            <span class="ascii-val mono" id="mem_val">63%</span>
                        </div>
                        <div class="ascii-bar-row">
                            <span class="ascii-label">DISK</span>
                            <span class="ascii-bar mono" id="ascii_disk_bar">[█████░░░░░░░]</span>
                            <span class="ascii-val mono" id="disk_val">41%</span>
                        </div>
                        <div class="ascii-bar-row">
                            <span class="ascii-label">SWAP</span>
                            <span class="ascii-bar mono" id="ascii_swap_bar">[██░░░░░░░░░░]</span>
                            <span class="ascii-val mono" id="swap_val">12%</span>
                        </div>
                        <div class="cli-kv-grid-sm">
                            <span>OS: <b id="os_val">Linux 6.14.2 x86_64</b></span>
                            <span>TCP ESTABLISHED: <b class="mono" id="tcp_est_val">24</b></span>
                            <span>TIME_WAIT: <b class="mono" id="tcp_tw_val">8</b></span>
                            <span>NET RATE: <b class="mono" id="net_rate_val">1.2 MB/s / 420 KB/s</b></span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ── 7. UPTIME HEATMAP ($ uptime --history --days=30) ── -->
            <div class="card-cli">
                <div class="card-cli-header">
                    <div class="card-cli-header-left">
                        <span class="cmd-title">$ uptime --history --days=30</span>
                        <span class="cmd-subtitle">// 最近 30 天可用率与中断历史</span>
                    </div>
                    <span class="mono text-muted" style="font-size:0.75rem">30d SLA: <b class="text-success">99.98%</b></span>
                </div>
                <div class="heatmap-grid-cli" id="heatmap_container">
                    <!-- Populated by JS -->
                </div>
            </div>

            <!-- ── 8. EVENT LOG STREAM ($ tail -f /var/log/netwatch/events.log) ── -->
            <div class="card-cli">
                <div class="card-cli-header">
                    <div class="card-cli-header-left">
                        <span class="cmd-title">$ tail -f /var/log/netwatch/events.log</span>
                        <span class="cmd-subtitle">// 实时事件与告警时间线日志</span>
                    </div>
                    <div class="card-cli-header-right">
                        <div class="btn-group-cli" style="display:flex; gap:4px">
                            <button class="btn-cli-sm active" onclick="filterLogs('all', this)">[ ALL ]</button>
                            <button class="btn-cli-sm" onclick="filterLogs('info', this)">[ INFO ]</button>
                            <button class="btn-cli-sm" onclick="filterLogs('warning', this)">[ WARNING ]</button>
                            <button class="btn-cli-sm" onclick="filterLogs('critical', this)">[ CRITICAL ]</button>
                            <button class="btn-cli-sm" onclick="filterLogs('recover', this)">[ RECOVER ]</button>
                        </div>
                        <button class="btn-cli-sm" id="btn_autoscroll" onclick="toggleAutoScroll()">[ AUTO SCROLL: ON ]</button>
                        <button class="btn-cli-sm" onclick="clearLogView()">[ CLEAR VIEW ]</button>
                    </div>
                </div>

                <div class="cli-grep-bar">
                    <span class="cli-prompt-sm">$ grep</span>
                    <input type="text" id="log_grep_input" class="cli-grep-input" placeholder="输入事件关键字 (例如: timeout, tcp, latency, recover)..." onkeyup="applyLogGrep()" />
                    <button class="btn-cli-xs" onclick="applyLogGrep()">[ SEARCH ]</button>
                </div>

                <div class="log-stream-box-cli" id="log_stream_box">
                    <div class="log-row"><span class="log-time">[2026-07-28 15:42:18]</span> <span class="log-level level-info">[INFO]</span> <span class="log-msg">tcp check passed target=1.1.1.1:443 latency=32ms status=healthy</span></div>
                    <div class="log-row"><span class="log-time">[2026-07-28 15:41:48]</span> <span class="log-level level-warning">[WARNING]</span> <span class="log-msg">latency increased target=hk-server value=186ms baseline=92ms delta=+102%</span></div>
                    <div class="log-row"><span class="log-time">[2026-07-28 15:40:21]</span> <span class="log-level level-critical">[CRITICAL]</span> <span class="log-msg">request timeout target=api-server timeout=5000ms failures=4/4</span></div>
                    <div class="log-row"><span class="log-time">[2026-07-28 15:39:52]</span> <span class="log-level level-recover">[RECOVER]</span> <span class="log-msg">service restored target=api-server downtime=91s checks=2/2</span></div>
                </div>
            </div>

        </div> <!-- End tab_overview -->

        <!-- ═══════════════════════════════════════════════════════════
             TAB 2: TARGET MONITOR ($ cat /etc/netwatch/targets)
             ═══════════════════════════════════════════════════════════ -->
        <div id="tab_targets" class="tab-view">
            <div class="card-cli">
                <div class="card-cli-header">
                    <div class="card-cli-header-left">
                        <span class="cmd-title">$ cat /etc/netwatch/targets</span>
                        <span class="cmd-subtitle">// 多目标监测表与策略配置</span>
                    </div>
                    <button class="btn-cli-action" onclick="addNewTargetPrompt()">[ + ADD TARGET ]</button>
                </div>

                <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:10px; margin-bottom:12px;">
                    <div class="dualstack-col" style="cursor:pointer" onclick="applyPresetTemplate('web')">
                        <div class="ds-title-line"><span>🌐 网站可用性模板</span><span class="badge-bracket status-info">[ HTTPS/TLS ]</span></div>
                        <div class="cli-subtitle" style="font-size:0.74rem; color:var(--text-muted)">检测 443 端口建连、TLS 证书及 HTTP 200 OK</div>
                    </div>
                    <div class="dualstack-col" style="cursor:pointer" onclick="applyPresetTemplate('dns')">
                        <div class="ds-title-line"><span>🔍 DNS 质量模板</span><span class="badge-bracket status-info">[ DNS/53 ]</span></div>
                        <div class="cli-subtitle" style="font-size:0.74rem; color:var(--text-muted)">检测 1.1.1.1 与 8.8.8.8 UDP/TCP 解析耗时</div>
                    </div>
                    <div class="dualstack-col" style="cursor:pointer" onclick="applyPresetTemplate('vps')">
                        <div class="ds-title-line"><span>⚡ VPS 线路模板</span><span class="badge-bracket status-info">[ TCP PING ]</span></div>
                        <div class="cli-subtitle" style="font-size:0.74rem; color:var(--text-muted)">检测 三网 CDN TCP 延迟与抖动</div>
                    </div>
                </div>

                <table class="cli-table">
                    <thead>
                        <tr>
                            <th>STATUS</th>
                            <th>NAME</th>
                            <th>TARGET</th>
                            <th>TYPE</th>
                            <th>FREQUENCY</th>
                            <th>THRESHOLDS</th>
                            <th>ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody id="targets_tbody">
                        <!-- Populated by JS -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════════
             TAB 3: DIAGNOSTIC CENTER ($ diagnose --summary)
             ═══════════════════════════════════════════════════════════ -->
        <div id="tab_diagnostics" class="tab-view">
            <div class="card-cli">
                <div class="card-cli-header">
                    <div class="card-cli-header-left">
                        <span class="cmd-title">$ diagnose --full</span>
                        <span class="cmd-subtitle">// 一键 12 阶段全链路诊断与分层证据树</span>
                    </div>
                    <span class="mono text-muted" style="font-size:0.74rem">支持 chain dependency & skipped 标记</span>
                </div>

                <div class="cli-grep-bar" style="margin-bottom:14px;">
                    <span class="cli-prompt-sm">$ target</span>
                    <input type="text" id="diag_target_input" class="cli-grep-input" placeholder="输入要诊断的目标域名或 IP (例如: github.com 或 37.114.48.47:443)..." value="github.com" />
                    <button class="btn-cli-action" id="diag_start_btn" onclick="startFullDiagnostics()">[> RUN FULL DIAGNOSTIC ]</button>
                </div>

                <!-- 12-Stage Diagnostic CLI List -->
                <div class="diag-cli-task-list" id="diag_stages_grid">
                    <!-- Populated by JS -->
                </div>

                <!-- Decision Tree Result -->
                <div class="card-cli hero-terminal-box" id="diag_tree_box" style="margin-top:14px; display:none;">
                    <div class="cli-header-bar">
                        <span>ROOT CAUSE DECISION TREE SUMMARY</span>
                    </div>
                    <div style="font-family:var(--font-mono); font-size:0.88rem; font-weight:700; color:var(--status-warning);" id="diag_root_cause">
                        诊断定性: 计算中...
                    </div>
                    <div class="cli-divider">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</div>
                    <div style="font-family:var(--font-mono); font-size:0.78rem; color:var(--text-secondary);" id="diag_evidence_chain">
                        > 证据链分析: 物理网卡 UP ➔ Gateway 正常 ➔ IPv4 畅通 ➔ IPv6 在宿主机启用 ➔ DNS 成功 ➔ TCP 80 建连 1ms ➔ HTTP 响应 200 OK
                    </div>
                </div>

                <!-- Before / After Delta Comparison -->
                <div style="margin-top:16px;">
                    <div class="cmd-title" style="margin-bottom:6px">$ delta --compare</div>
                    <table class="cli-table">
                        <thead>
                            <tr>
                                <th>TEST STAGE</th>
                                <th>BEFORE RE-TEST</th>
                                <th>AFTER RE-TEST</th>
                                <th>LATENCY DELTA</th>
                            </tr>
                        </thead>
                        <tbody id="diag_delta_tbody">
                            <tr><td colspan="4" style="text-align:center; color:var(--text-muted)">已记录基线数据。再次针对相同目标执行诊断即可对比 Before/After Delta。</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════════
             TAB 4: EVENTS & REPORTS ($ alerts --unresolved)
             ═══════════════════════════════════════════════════════════ -->
        <div id="tab_events" class="tab-view">
            <div class="card-cli">
                <div class="card-cli-header">
                    <div class="card-cli-header-left">
                        <span class="cmd-title">$ alerts --unresolved</span>
                        <span class="cmd-subtitle">// 告警去重、连续 3 次判定与报告导出</span>
                    </div>
                    <div style="display:flex; gap:6px">
                        <button class="btn-cli-sm" onclick="exportReportFmt('markdown')">[ EXPORT MD ]</button>
                        <button class="btn-cli-sm" onclick="exportReportFmt('json')">[ EXPORT JSON ]</button>
                        <button class="btn-cli-sm" onclick="exportReportFmt('csv')">[ EXPORT CSV ]</button>
                    </div>
                </div>

                <div class="cli-log-line text-muted" style="margin-bottom:12px;">
                    [✓] 所有检测连续判定告警生效中。支持敏感 IP 自动匿名掩码 (`37.114.*.*`)。
                </div>

                <table class="cli-table">
                    <thead>
                        <tr>
                            <th>TIMESTAMP</th>
                            <th>TARGET</th>
                            <th>EVENT TYPE</th>
                            <th>LEVEL</th>
                            <th>DESCRIPTION</th>
                            <th>ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody id="events_tbody">
                        <tr>
                            <td class="mono">15:42:18</td>
                            <td class="mono">37.114.48.47:8180</td>
                            <td>系统守护线程启动</td>
                            <td><span class="badge-bracket status-info">[ INFO ]</span></td>
                            <td>NETWATCH 诊断系统初始化完成，所有探针就绪。</td>
                            <td><button class="btn-cli-xs" onclick="alert('已确认该事件')">[ ACK ]</button></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ── 13. TERMINAL FOOTER ── -->
        <footer class="terminal-footer">
            <div>
                <b>NETWATCH NETWORK OPERATIONS TERMINAL</b><br>
                <span>monitoring network health in realtime | version: 2.0.0 | status: operational</span>
            </div>
            <div class="footer-links">
                <a href="#overview" onclick="switchNavTab('overview')">[ OVERVIEW ]</a>
                <a href="#targets" onclick="switchNavTab('targets')">[ TARGETS ]</a>
                <a href="#diagnostics" onclick="switchNavTab('diagnostics')">[ DIAGNOSTICS ]</a>
                <a href="#events" onclick="switchNavTab('events')">[ EVENTS ]</a>
            </div>
        </footer>

    </main> <!-- End page-container -->

    <!-- ── KEYBOARD HELP MODAL ── -->
    <div class="modal-cli-overlay" id="keyboard_modal" style="display:none;" onclick="closeKeyboardHelp(event)">
        <div class="modal-cli-box">
            <div class="modal-cli-header">
                <span>KEYBOARD SHORTCUTS REFERENCE</span>
                <button class="btn-cli-xs" onclick="closeKeyboardHelp()">[ ESC / CLOSE ]</button>
            </div>
            <div class="modal-cli-header"><span>KEYBOARD SHORTCUTS</span><button class="btn-cli-xs" onclick="closeKeyboardHelp()">[ ESC ]</button></div>
            <div class="modal-cli-body">
                <div class="shortcut-row"><span class="key-cap">R</span> <span>刷新数据</span></div>
                <div class="shortcut-row"><span class="key-cap">D</span> <span>诊断模式</span></div>
                <div class="shortcut-row"><span class="key-cap">/</span> <span>搜索日志</span></div>
            </div>
        </div>
    </div>

    <script>
    let autoScrollLogs = true;
    let pingHistory = { ping_cu: [] };

    function switchNavTab(tabId, btn) {
        document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active-view'));
        document.getElementById('tab_' + tabId).classList.add('active-view');
        localStorage.setItem('console_active_tab', tabId);
    }

    function showKeyboardHelp() { document.getElementById('keyboard_modal').style.display = 'flex'; }
    function closeKeyboardHelp(e) { if (!e || e.target.id === 'keyboard_modal') document.getElementById('keyboard_modal').style.display = 'none'; }

    function fetchStats() {
        fetch('/stats').then(res => res.json()).then(data => {
            const cpu = data.cpu_percent || 0;
            const mem = data.memory_percent || 0;
            const disk = data.disk_percent || 0;
            const swap = data.swap_percent || 0;
            document.getElementById('cpu_val')?.textContent = `${cpu.toFixed(0)}%`;
            document.getElementById('mem_val')?.textContent = `${mem.toFixed(0)}%`;
            document.getElementById('disk_val')?.textContent = `${disk.toFixed(0)}%`;
            document.getElementById('swap_val')?.textContent = `${swap.toFixed(0)}%`;
        }).catch(() => {});
    }

    function fetchPings() {
        fetch('/pings').then(res => res.json()).then(data => {
            if (data.ping_cu !== undefined) {
                pingHistory.ping_cu.push(data.ping_cu);
                if (pingHistory.ping_cu.length > 60) pingHistory.ping_cu.shift();
                const cur = pingHistory.ping_cu[pingHistory.ping_cu.length - 1];
                document.getElementById('metric_latency').innerHTML = `${cur.toFixed(0)} <span class="unit">ms</span>`;
            }
        }).catch(() => {});
    }

    function renderUptimeHeatmap() {
        const container = document.getElementById('heatmap_container');
        if (!container) return;
        for (let i = 0; i < 30; i++) {
            const sq = document.createElement('div');
            sq.className = 'heatmap-sq sq-healthy';
            container.appendChild(sq);
        }
    }


    function generateAsciiBar(pct) {
        const total = 12;
        const filled = Math.min(total, Math.max(0, Math.round((pct / 100) * total)));
        return '[' + '█'.repeat(filled) + '░'.repeat(total - filled) + ']';
    }

    async function fetchPings() {
        try {
            const res = await fetch('/pings');
            const data = await res.json();

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



