from flask import Flask, render_template_string, jsonify
import psutil, socket, os
from datetime import datetime

app = Flask(__name__)
start_time = datetime.now()
host_boot_time = datetime.fromtimestamp(psutil.boot_time())

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ hostname }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: black; color: #00FF00; font-family: monospace;
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
        .stats { margin-top: 20px; line-height: 1.4; }
        .label { color: #00cc00; }
        .value { color: #fff; }
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
        <pre class="stats">
<span class="label">Hostname        :</span> <span class="value" id="hostname"></span>
<span class="label">CPU Usage       :</span> <span class="value" id="cpu"></span>
<span class="label">Memory Usage    :</span> <span class="value" id="memory"></span>
<span class="label">Disk Usage      :</span> <span class="value" id="disk"></span>
<span class="label">Container Uptime:</span> <span class="value" id="cuptime"></span>
<span class="label">Host Uptime     :</span> <span class="value" id="huptime"></span>
<span class="label">CPU Cores       :</span> <span class="value" id="cores"></span>
<span class="label">Load Average    :</span> <span class="value" id="load"></span>
<span class="label">IP Address      :</span> <span class="value" id="ip"></span>
<span class="label">Message         :</span> <span class="value">{{ message }}</span>

<span class="terminal-line">root@{{ hostname }}:~/console-web-v1.6# <span class="cursor"></span></span>
        </pre>
    </div>
    <script>
    async function fetchStats() {
        const res = await fetch('/stats');
        const data = await res.json();
        document.getElementById('hostname').textContent = data.hostname;
        document.getElementById('cpu').textContent = data.cpu + '%';
        document.getElementById('memory').textContent = data.memory + '%';
        document.getElementById('disk').textContent = data.disk + '%';
        document.getElementById('cuptime').textContent = data.container_uptime + 's';
        document.getElementById('huptime').textContent = data.host_uptime + 's';
        document.getElementById('cores').textContent = data.cores;
        document.getElementById('load').textContent = data.load;
        document.getElementById('ip').textContent = data.ip;
    }
    fetchStats();
    setInterval(fetchStats, 1000);
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    hostname = socket.gethostname()
    message = os.getenv("CUSTOM_MSG", "console-web v1.6 running")
    return render_template_string(TEMPLATE, hostname=hostname, message=message)


@app.route("/stats")
def stats():
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    container_uptime = int((datetime.now() - start_time).total_seconds())
    host_uptime = int((datetime.now() - host_boot_time).total_seconds())
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    cores = psutil.cpu_count()
    load1, load5, load15 = os.getloadavg()
    load = f"{load1:.2f}, {load5:.2f}, {load15:.2f}"
    return jsonify(cpu=cpu, memory=mem, disk=disk, container_uptime=container_uptime,
                   host_uptime=host_uptime, hostname=hostname, ip=ip, cores=cores, load=load)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
