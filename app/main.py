from flask import Flask, render_template_string
import psutil, socket, os
from datetime import datetime

app = Flask(__name__)
start_time = datetime.now()

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
        <pre>
Hostname    : {{ hostname }}
CPU Usage   : {{ cpu }}%
Memory Usage: {{ memory }}%
Disk Usage  : {{ disk }}%
Uptime      : {{ uptime }} seconds
IP Address  : {{ ip }}
Message     : {{ message }}

<span class="terminal-line">root@{{ hostname }}:~/console-web-v1.5# <span class="cursor"></span></span>
        </pre>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    uptime = int((datetime.now() - start_time).total_seconds())
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    message = os.getenv("CUSTOM_MSG", "console-web v1.5 enhanced running")
    return render_template_string(TEMPLATE, cpu=cpu, memory=mem, disk=disk,
                                  uptime=uptime, hostname=hostname, ip=ip, message=message)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
