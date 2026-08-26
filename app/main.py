import os
import socket
import logging
from pathlib import Path
from app import app, logger, acme_manager

def run_flask_fallback():
    try:
        logger.info("Starting Flask server on [::]:8080 (IPv6 & IPv4 dual-stack)...")
        app.run(host="::", port=8080, threaded=True)
    except Exception as e:
        logger.warning("Failed to bind host '::', falling back to 0.0.0.0: %s", e)
        app.run(host="0.0.0.0", port=8080, threaded=True)

if __name__ == "__main__":
    acme_manager._auto_init()
    cert_file = acme_manager.FULLCHAIN_FILE if acme_manager.FULLCHAIN_FILE.exists() else acme_manager.CERT_FILE
    key_file = acme_manager.KEY_FILE

    gunicorn_bin = "/usr/local/bin/gunicorn"
    if not Path(gunicorn_bin).exists():
        gunicorn_bin = "gunicorn"

    bind_addr = "[::]:8080"

    if cert_file.exists() and key_file.exists():
        logger.info("🔒 SSL Certificate present (%s). Launching Gunicorn HTTPS server on %s...", cert_file, bind_addr)
        try:
            os.execvp(gunicorn_bin, [
                "gunicorn", "-b", bind_addr,
                "--certfile", str(cert_file),
                "--keyfile", str(key_file),
                "--workers", "2",
                "--timeout", "120",
                "app.main:app"
            ])
        except Exception as e:
            logger.warning("Failed to exec gunicorn HTTPS: %s, falling back to Flask", e)
            run_flask_fallback()
    else:
        logger.info("🔓 No SSL Certificate found yet. Launching Gunicorn HTTP server on %s...", bind_addr)
        try:
            os.execvp(gunicorn_bin, [
                "gunicorn", "-b", bind_addr,
                "--workers", "2",
                "--timeout", "120",
                "app.main:app"
            ])
        except Exception as e:
            logger.warning("Failed to exec gunicorn HTTP: %s, falling back to Flask", e)
            run_flask_fallback()

