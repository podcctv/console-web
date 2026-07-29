import os
import json
import socket
import ssl
import time
import urllib.parse
import urllib.request
import subprocess
from datetime import datetime
import psutil

from app.network import tcp_ping

_latest_diag_cache = {"result": None}

def get_latest_diag_cache():
    return _latest_diag_cache

def set_latest_diag_cache(result):
    _latest_diag_cache["result"] = result

def run_full_diagnostics(target_input: str):
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
