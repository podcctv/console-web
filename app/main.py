from flask import Flask, render_template_string, jsonify, Response, stream_with_context, request
import psutil, socket, os, urllib.request, urllib.parse, platform, json, subprocess, shlex
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

COMMANDS = {
    "ping": lambda target, extra: ["ping", *extra, target]
    if extra
    else ["ping", "-c", "4", target],
    "mtr": lambda target, extra: ["mtr", *extra, target]
    if extra
    else ["mtr", "-w", "-c", "5", target],
    # Use the official Speedtest CLI instead of the Python speedtest-cli
    "speedtest": lambda target, extra: [
        "speedtest",
        "--progress=no",
        "--accept-license",
        "--accept-gdpr",
        *extra,
    ],
}

@app.route("/run/<cmd>")
def run_cmd(cmd):
    target = request.args.get("target", "")
    raw_args = request.args.get("args", "")
    if cmd not in COMMANDS:
        return Response("unsupported command", status=400)
    if cmd != "speedtest" and not target:
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


def query_isp(ip: str):
    try:
        with urllib.request.urlopen(
            f"http://ip-api.com/json/{ip}?fields=isp", timeout=2
        ) as resp:
            return json.loads(resp.read().decode()).get("isp")
    except Exception:
        return None


@app.route("/pinginfo")
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
    return jsonify(ip=ip, isp=isp, ping=latency)


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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body { height: 100%; overflow: hidden; }
        body {
            background: black; color: #00FF00; font-family: 'Consolas', monospace;
            display: flex; flex-direction: column; align-items: center; justify-content: center;
            height: 100%; padding: 10px;
        }
        .window {
            border: 1px solid #00FF00; width: 80%; max-width: 900px; padding: 20px;
            box-shadow: 0 0 20px #00FF00; border-radius: 8px;
            position: relative; background: black;
            height: 100%; overflow: hidden; display: flex; flex-direction: column;
        }
        pre { overflow-x: auto; }
        .window-bar {
            display: flex; gap: 8px; position: absolute; top: 10px; left: 10px;
        }
        .window-btn { width: 12px; height: 12px; border-radius: 50%; display: inline-block; }
        .red { background: #ff5f56; }
        .yellow { background: #ffbd2e; }
        .green { background: #27c93f; }
        .banner { margin-bottom: 20px; }
        .stats {
            margin-top: 20px; line-height: 1.4;
            flex: 1; display: flex; flex-direction: column; overflow-y: auto;
        }
        .label { color: #00cc00; }
        .value { color: #fff; }
        .ping-chart { margin-left: 8px; background: #000; }
        .terminal-line { margin-top: 20px; }
        #cmd_output { display: block; white-space: pre-wrap; margin-top: 10px; flex: 1; overflow-y: auto; }
        .terminal-input {
            background: black; color: #00FF00; font-family: 'Consolas', monospace;
            border: none; outline: none; caret-color: #00FF00; caret-shape: block;
        }
        /* Custom scrollbar styling */
        .stats::-webkit-scrollbar,
        #cmd_output::-webkit-scrollbar {
            width: 8px;
        }
        .stats::-webkit-scrollbar-track,
        #cmd_output::-webkit-scrollbar-track {
            background: #001100;
        }
        .stats::-webkit-scrollbar-thumb,
        #cmd_output::-webkit-scrollbar-thumb {
            background: #00FF00;
            border-radius: 4px;
        }
        .stats::-webkit-scrollbar-thumb:hover,
        #cmd_output::-webkit-scrollbar-thumb:hover {
            background: #00cc00;
        }
        .stats {
            scrollbar-color: #00FF00 #001100;
            scrollbar-width: thin;
        }
        #cmd_output {
            scrollbar-color: #00FF00 #001100;
            scrollbar-width: thin;
        }
        @media (max-width: 600px) {
            .window { width: 100%; padding: 10px; }
            pre { font-size: 12px; }
            .window-bar { top: 5px; left: 5px; }
        }
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
    _   ______  ____  ______   _____ ______________ __ __________
   / | / / __ \/ __ \/ ____/  / ___// ____/ ____/ //_// ____/ __ \
  /  |/ / / / / / / / __/     \__ \/ __/ / __/ / ,<  / __/ / /_/ /
 / /|  / /_/ / /_/ / /___    ___/ / /___/ /___/ /| |/ /___/ _, _/
/_/ |_|\____/_____/_/____/   /____/_____/_____/_/ |_|_/____/_/ |_|

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
<span id="client_ip_line"><span class="label">Client IP       :</span> <span class="value" id="client_ip"></span></span>
<span id="client_ping_line"><span class="label">Ping Client     :</span> <span class="value" id="client_ping"></span></span>
<span id="disk_io_line"><span class="label">Disk IO (R/W)  :</span> <span class="value" id="disk_io"></span></span>
<span id="net_io_line"><span class="label">Net IO (Up/Down):</span> <span class="value" id="net_io"></span></span>

<span id="ping_cu_line"><span class="label">Ping 浙江联通 :</span> <span class="value" id="ping_cu"></span> <canvas class="ping-chart" id="ping_cu_chart" width="100" height="40"></canvas>
</span><span id="ping_cm_line"><span class="label">Ping 浙江移动 :</span> <span class="value" id="ping_cm"></span> <canvas class="ping-chart" id="ping_cm_chart" width="100" height="40"></canvas>
</span><span id="ping_ct_line"><span class="label">Ping 浙江电信 :</span> <span class="value" id="ping_ct"></span> <canvas class="ping-chart" id="ping_ct_chart" width="100" height="40"></canvas>
</span>

<span id="ping_legend_line"><span class="label">Ping 图例     :</span> <span class="value"><span style="color:#00ff00">低 (&lt;80ms)</span> <span style="color:#ffff00">中 (&lt;160ms)</span> <span style="color:#ff0000">高 (&ge;160ms)</span></span></span>

<span id="os_line"><span class="label">OS              :</span> <span class="value" id="os"></span>
</span><span id="kernel_line"><span class="label">Kernel          :</span> <span class="value" id="kernel"></span>
</span><span id="arch_line"><span class="label">Architecture    :</span> <span class="value" id="arch"></span>
</span><span id="cpu_model_line"><span class="label">CPU Model       :</span> <span class="value" id="cpu_model"></span>
</span><span id="mem_total_line"><span class="label">Total Memory    :</span> <span class="value" id="mem_total"></span>
</span><span id="disk_total_line"><span class="label">Total Disk      :</span> <span class="value" id="disk_total"></span>
</span>

<span id="cmd_output"></span>
<span class="terminal-line">root@Hostdzire:~/console-web-v1.6# <input id="cmd_input" class="terminal-input" autofocus placeholder="type 'help'" /></span>
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
        setStat('client_ip', data.client_ip);
        const cp = data.client_ping === null ? 'N/A' : data.client_ping;
        setStat(
            'client_ping',
            cp,
            v => (typeof v === 'number' ? `${v.toFixed(1)}ms` : v),
            v => (typeof v === 'number' ? pingColor(v) : '#ff0000')
        );
        setStat('disk_io', data.disk_io);
        setStat('net_io', data.net_io);
        const pings = [data.ping_cu, data.ping_cm, data.ping_ct];
        const maxPing = Math.max(...pings.map(v => (v === null || v === undefined ? 0 : v))) || 1;
        setPing('ping_cu', data.ping_cu, maxPing);
        setPing('ping_cm', data.ping_cm, maxPing);
        setPing('ping_ct', data.ping_ct, maxPing);
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
    const PROMPT = 'root@Hostdzire:~/console-web-v1.6#';

    function bar(pct, width = 20) {
        const filled = pct > 0 ? Math.max(1, Math.round(width * pct / 100)) : 0;
        return '[' + '#'.repeat(filled) + '.'.repeat(width - filled) + ']';
    }

    function htopColor(pct) {
        if (pct < 40) return '#00ff00';
        if (pct < 75) return '#ffff00';
        return '#ff0000';
    }

    function pingBar(ms, max) {
        const pct = Math.min(ms, max) / max * 100;
        return bar(pct);
    }

    function pingColor(ms) {
        if (ms < 80) return '#00ff00';
        if (ms < 160) return '#ffff00';
        return '#ff0000';
    }

    function setPing(id, ms, maxPing) {
        const line = document.getElementById(id + '_line');
        const el = document.getElementById(id);
        const canvas = document.getElementById(id + '_chart');
        if (line) line.style.display = '';
        const display = ms === null || ms === undefined ? maxPing : ms;
        const val = ms === null || ms === undefined ? 'N/A' : `${ms.toFixed(1)}ms`;
        const barText = pingBar(display, maxPing);
        el.textContent = `${val.padEnd(8)} ${barText}`;
        el.style.color = ms === null || ms === undefined ? '#ff0000' : pingColor(ms);
        if (canvas) {
            pingHistory[id].push(ms);
            if (pingHistory[id].length > 50) pingHistory[id].shift();
            drawChart(canvas, pingHistory[id], maxPing);
        }
    }

    function drawChart(canvas, data, maxPing) {
        const ctx = canvas.getContext('2d');
        const width = canvas.width;
        const height = canvas.height;
        ctx.clearRect(0, 0, width, height);
        const barWidth = Math.max(1, Math.floor(width / 50));
        data.forEach((v, i) => {
            const val = v === null || v === undefined ? maxPing : v;
            const h = Math.min(val, maxPing) / maxPing * height;
            ctx.fillStyle = v === null || v === undefined ? '#ff0000' : pingColor(v);
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

    let currentSource;
    function runCommand(cmd, target = '', args = '') {
        if (currentSource) currentSource.close();
        const output = document.getElementById('cmd_output');
        const commandText = [cmd, target, args].filter(Boolean).join(' ');
        output.insertAdjacentText('beforeend', `${PROMPT} ${commandText}\n`);
        output.scrollTop = output.scrollHeight;
        let url = `/run/${cmd}`;
        const params = [];
        if (target) params.push(`target=${encodeURIComponent(target)}`);
        if (args) params.push(`args=${encodeURIComponent(args)}`);
        if (params.length) url += `?${params.join('&')}`;
        currentSource = new EventSource(url);
        currentSource.onmessage = e => {
            const data = e.data;
            if (!data.startsWith('[exit')) {
                output.insertAdjacentText('beforeend', data + '\n');
                output.scrollTop = output.scrollHeight;
            } else {
                currentSource.close();
            }
        };
        currentSource.onerror = () => {
            output.insertAdjacentText('beforeend', 'command failed\n');
            output.scrollTop = output.scrollHeight;
            currentSource.close();
        };
    }

    const inputEl = document.getElementById('cmd_input');
    const outputEl = document.getElementById('cmd_output');
    outputEl.textContent = "Hint: Type 'help' for available commands\n";
    inputEl.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            const text = inputEl.value.trim();
            if (!text) return;
            const [cmd, ...args] = text.split(/\s+/);
            switch (cmd) {
                case 'ping':
                case 'mtr':
                    if (args.length) {
                        runCommand(cmd, args.join(' '));
                    } else {
                        outputEl.insertAdjacentText('beforeend', `${PROMPT} ${text}\nmissing target\n`);
                    }
                    break;
                case 'speedtest':
                    runCommand('speedtest', '', args.join(' '));
                    break;
                case 'help':
                    outputEl.insertAdjacentText('beforeend', `${PROMPT} ${text}\n` +
                        'Available commands:\n' +
                        '  ping <host>\n' +
                        '  mtr <host>\n' +
                        '  speedtest [args]\n' +
                        '  help\n');
                    break;
                default:
                    outputEl.insertAdjacentText('beforeend', `${PROMPT} ${text}\ncommand not found\n`);
            }
            outputEl.scrollTop = outputEl.scrollHeight;
            inputEl.value = '';
        }
    });
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
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    client_ping = icmp_ping(client_ip) if client_ip else None
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
        client_ip=client_ip,
        client_ping=client_ping,
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
