from flask import Flask, render_template_string, jsonify
import psutil, socket, os, urllib.request, platform, json
from datetime import datetime

app = Flask(__name__)
start_time = datetime.now()
host_boot_time = datetime.fromtimestamp(psutil.boot_time())

# Track last network counters to compute realtime speed
try:
    _last_net = psutil.net_io_counters()
except Exception:
    _last_net = None
_last_time = datetime.now()


def get_isp_name():
    try:
        with urllib.request.urlopen(
            "http://ip-api.com/json/?fields=isp", timeout=2
        ) as resp:
            name = json.loads(resp.read().decode()).get("isp")
            if name:
                # Return a short form like "Hostdzire" instead of the full company name
                return name.split()[0]
            return None
    except Exception:
        return None


ISP_NAME = get_isp_name()

PING_TARGETS = {
    "ping_cu": "zj-cu-v4.ip.zstaticcdn.com:80",
    "ping_cm": "zj-cm-v4.ip.zstaticcdn.com:80",
    "ping_ct": "zj-ct-v4.ip.zstaticcdn.com:80",
}


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


def humanize_bytes(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}EB"

TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ hostname }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: black; color: #00FF00; font-family: 'Consolas', monospace;
            display: flex; flex-direction: column; align-items: center; justify-content: center;
            height: 100vh;
        }
        .window {
            border: 1px solid #00FF00; width: 80%; padding: 20px;
            box-shadow: 0 0 20px #00FF00; border-radius: 8px;
            position: relative; background: black;
        }
        .window-bar {
            display: flex; gap: 8px; position: absolute; top: 10px; left: 10px;
        }
        .window-btn { width: 12px; height: 12px; border-radius: 50%; display: inline-block; }
        .red { background: #ff5f56; }
        .yellow { background: #ffbd2e; }
        .green { background: #27c93f; }
        .banner { margin-bottom: 20px; }
        .stats { margin-top: 20px; line-height: 1.4; }
        .label { color: #00cc00; }
        .value { color: #fff; }
        .ping-chart { margin-left: 8px; background: #000; }
        .terminal-line { margin-top: 20px; }
        .cursor {
            display: inline-block; width: 10px; height: 1em;
            background: #00FF00; animation: blink 1s steps(1) infinite;
        }
        @keyframes blink { 50% { background: transparent; } }
    </style>
</head>
<body>
    <div class="window">
        <div class="window-bar">
            <div class="window-btn red"></div>
            <div class="window-btn yellow"></div>
            <div class="window-btn green"></div>
        </div>
        <pre class="banner">
   ___  ____  _____ ____  _      ____  ____   ___  ____  _____ ____  
  / _ \|  _ \| ____|  _ \| |    / ___||  _ \ / _ \|  _ \| ____|  _ \ 
 | | | | | | |  _| | |_) | |    \___ \| |_) | | | | | | |  _| | |_) |
 | |_| | |_| | |___|  __/| |___  ___) |  _ <| |_| | |_| | |___|  _ < 
  \___/|____/|_____|_|   |_____|____/|_| \_\\___/|____/|_____|_| \_\
    

Welcome to console-web 😎
Running on coffee ☕, duct tape 🛠️, and blind optimism 🤖.
    

Tips:
- Don't press F12, we *see* you.
- If something breaks, blame the intern.
- Made with ❤️ by the ghost in the machine.
    

✨ Initiating sarcasm protocol...
🤖 AI self-esteem module: [ERROR: Not Found]
📟 System Check: 404 - Humility Not Installed
    

To exit reality, press ALT+F4. Good luck.
        </pre>
        <pre class="stats">
<span id="hostname_line"><span class="label">ISP             :</span> <span class="value" id="hostname"></span></span>
<span id="cpu_line"><span class="label">CPU Usage       :</span> <span class="value" id="cpu"></span></span>
<span id="memory_line"><span class="label">Memory Usage    :</span> <span class="value" id="memory"></span></span>
<span id="disk_line"><span class="label">Disk Usage      :</span> <span class="value" id="disk"></span></span>
<span id="cuptime_line"><span class="label">Container Uptime:</span> <span class="value" id="cuptime"></span></span>
<span id="huptime_line"><span class="label">Host Uptime     :</span> <span class="value" id="huptime"></span></span>
<span id="cores_line"><span class="label">CPU Cores       :</span> <span class="value" id="cores"></span></span>
<span id="load_line"><span class="label">Load Average    :</span> <span class="value" id="load"></span></span>
<span id="ip_line"><span class="label">IP Address      :</span> <span class="value" id="ip"></span></span>
<span id="disk_io_line"><span class="label">Disk IO (R/W)  :</span> <span class="value" id="disk_io"></span></span>
<span id="net_io_line"><span class="label">Net IO (Up/Down):</span> <span class="value" id="net_io"></span></span>

<span id="ping_cu_line"><span class="label">Ping 浙江联通 :</span> <span class="value" id="ping_cu"></span> <canvas class="ping-chart" id="ping_cu_chart" width="100" height="40"></canvas>
</span><span id="ping_cm_line"><span class="label">Ping 浙江移动 :</span> <span class="value" id="ping_cm"></span> <canvas class="ping-chart" id="ping_cm_chart" width="100" height="40"></canvas>
</span><span id="ping_ct_line"><span class="label">Ping 浙江电信 :</span> <span class="value" id="ping_ct"></span> <canvas class="ping-chart" id="ping_ct_chart" width="100" height="40"></canvas>
</span>

<span id="os_line"><span class="label">OS              :</span> <span class="value" id="os"></span>
</span><span id="kernel_line"><span class="label">Kernel          :</span> <span class="value" id="kernel"></span>
</span><span id="arch_line"><span class="label">Architecture    :</span> <span class="value" id="arch"></span>
</span><span id="cpu_model_line"><span class="label">CPU Model       :</span> <span class="value" id="cpu_model"></span>
</span><span id="mem_total_line"><span class="label">Total Memory    :</span> <span class="value" id="mem_total"></span>
</span><span id="disk_total_line"><span class="label">Total Disk      :</span> <span class="value" id="disk_total"></span>
</span>

<span class="terminal-line">root@{{ hostname }}:~/console-web-v1.6# <span class="cursor"></span></span>
        </pre>
    </div>
    <script>
    function setStat(id, value, formatter, colorFn) {
        const line = document.getElementById(id + '_line');
        const el = document.getElementById(id);
        if (value === null || value === undefined || value === '') {
            if (line) line.style.display = 'none';
            return;
        }
        if (line) line.style.display = '';
        el.textContent = formatter ? formatter(value) : value;
        if (colorFn) el.style.color = colorFn(value);
    }

    async function fetchStats() {
        const res = await fetch('/stats');
        const data = await res.json();
        setStat('hostname', data.hostname);
        setStat('cpu', data.cpu, v => `${v.toFixed(1)}% ${bar(v)}`, htopColor);
        setStat('memory', data.memory, v => `${v.toFixed(1)}% ${bar(v)}`, htopColor);
        setStat('disk', data.disk, v => `${v.toFixed(1)}% ${bar(v)}`, htopColor);
        setStat('cuptime', data.container_uptime);
        setStat('huptime', data.host_uptime);
        setStat('cores', data.cores);
        setStat('load', data.load);
        setStat('ip', data.ip);
        setStat('disk_io', data.disk_io);
        setStat('net_io', data.net_io);
        setPing('ping_cu', data.ping_cu);
        setPing('ping_cm', data.ping_cm);
        setPing('ping_ct', data.ping_ct);
    }
    fetchStats();
    setInterval(fetchStats, 1000);

    async function fetchHost() {
        const res = await fetch('/host');
        const data = await res.json();
        setOrHide('os', data.system);
        setOrHide('kernel', data.release);
        setOrHide('arch', data.machine);
        setOrHide('cpu_model', data.processor);
        setOrHide('mem_total', data.total_memory);
        setOrHide('disk_total', data.total_disk);
    }
    fetchHost();

    const pingHistory = { ping_cu: [], ping_cm: [], ping_ct: [] };

    function bar(pct, width = 20) {
        const filled = pct > 0 ? Math.max(1, Math.round(width * pct / 100)) : 0;
        return '[' + '#'.repeat(filled) + '.'.repeat(width - filled) + ']';
    }

    function htopColor(pct) {
        if (pct < 40) return '#00ff00';
        if (pct < 75) return '#ffff00';
        return '#ff0000';
    }

    function pingBar(ms) {
        const max = 200;
        const pct = Math.min(ms, max) / max * 100;
        return bar(pct);
    }

    function pingColor(ms) {
        if (ms < 80) return '#00ff00';
        if (ms < 160) return '#ffff00';
        return '#ff0000';
    }

    function setPing(id, ms) {
        const line = document.getElementById(id + '_line');
        const el = document.getElementById(id);
        const canvas = document.getElementById(id + '_chart');
        if (line) line.style.display = '';
        const val = ms === null || ms === undefined ? 'N/A' : `${ms.toFixed(1)}ms`;
        const barText = ms === null || ms === undefined ? '[' + '#'.repeat(20) + ']' : pingBar(ms);
        el.textContent = `${val.padEnd(8)} ${barText}`;
        el.style.color = ms === null || ms === undefined ? '#ff0000' : pingColor(ms);
        if (ms !== null && ms !== undefined && canvas) {
            pingHistory[id].push(ms);
            if (pingHistory[id].length > 50) pingHistory[id].shift();
            drawChart(canvas, pingHistory[id]);
        }
    }

    function drawChart(canvas, data) {
        const ctx = canvas.getContext('2d');
        const width = canvas.width;
        const height = canvas.height;
        ctx.clearRect(0, 0, width, height);
        const max = 200;
        const barWidth = Math.max(1, Math.floor(width / 50));
        data.forEach((v, i) => {
            const h = Math.min(v, max) / max * height;
            ctx.fillStyle = pingColor(v);
            for (let y = height; y > height - h; y -= 4) {
                ctx.fillRect(i * barWidth, y - 3, barWidth - 1, 3);
            }
        });
    }

    function setOrHide(id, value) {
        const line = document.getElementById(id + '_line');
        const el = document.getElementById(id);
        if (value === null || value === undefined || value === '') {
            if (line) line.style.display = 'none';
        } else {
            if (line) line.style.display = '';
            el.textContent = value;
        }
    }
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    hostname = ISP_NAME or socket.gethostname()
    return render_template_string(TEMPLATE, hostname=hostname)


@app.route("/stats")
def stats():
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
    hostname = ISP_NAME or socket.gethostname()
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "N/A"
    try:
        public_ip = (
            urllib.request.urlopen("https://ifconfig.me", timeout=2)
            .read()
            .decode()
            .strip()
        )
    except Exception:
        public_ip = "N/A"
    if ip == "N/A" and public_ip == "N/A":
        ip_display = None
    else:
        ip_display = f"{ip} (公网 {public_ip})"
    try:
        cores = psutil.cpu_count()
    except Exception:
        cores = None
    try:
        load1, load5, load15 = os.getloadavg()
        load = f"{load1:.2f}, {load5:.2f}, {load15:.2f}"
    except Exception:
        load = None
    pings = {k: tcp_ping(v) for k, v in PING_TARGETS.items()}
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
        cores=cores,
        load=load,
        disk_io=disk_io,
        net_io=net_io,
        **pings,
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
