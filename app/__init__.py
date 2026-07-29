import os
import time
import logging
import platform
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from flask import Flask

from app.config import LOGS_DIR, PING_TARGETS, __version__
from app.tsdb import tsdb
from app import acme_manager
from app.network import tcp_ping

def configure_logging():
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOGS_DIR / "console-web.log"

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

start_time = datetime.now()

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    
    from app.routes import register_blueprints
    register_blueprints(app)
    
    return app

app = create_app()

# Start ACME Auto-renewal daemon thread
try:
    acme_manager.start_daemon()
except Exception as e:
    logger.warning("Failed to start ACME auto-renew daemon: %s", e)

# Start background ping sampler loop thread
def _ping_sampler_loop():
    while True:
        try:
            sample_lat = None
            for key, host in PING_TARGETS.items():
                res = tcp_ping(host)
                if res is not None:
                    sample_lat = res
                    break
            now_ts = time.time()
            tsdb.insert("global", now_ts, sample_lat)
        except Exception as e:
            logger.warning("Ping sampler daemon iteration error: %s", e)
        time.sleep(15)

_ping_thread = threading.Thread(target=_ping_sampler_loop, daemon=True)
_ping_thread.start()

logger.info(
    "console-web package initialized (pid=%s, platform=%s %s, python=%s, version=%s)",
    os.getpid(),
    platform.system(),
    platform.release(),
    platform.python_version(),
    __version__,
)
