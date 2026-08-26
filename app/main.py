import os
import socket
import logging
from pathlib import Path
from app import app, logger, acme_manager

def run_flask_fallback():
    try:
        logger.info("Starting Flask server on 0.0.0.0:8080...")
        app.run(host="0.0.0.0", port=8080, threaded=True)
    except Exception as e:
        logger.error("Failed to bind Flask server: %s", e)

if __name__ == "__main__":
    is_valid_cert = acme_manager._cert_is_valid(min_days=1)
    cert_file = acme_manager.FULLCHAIN_FILE if acme_manager.FULLCHAIN_FILE.exists() else acme_manager.CERT_FILE
    key_file = acme_manager.KEY_FILE

    gunicorn_bin = "/usr/local/bin/gunicorn"
    if not Path(gunicorn_bin).exists():
        gunicorn_bin = "gunicorn"

    bind_addr = "0.0.0.0:8080"

    if is_valid_cert and cert_file.exists() and key_file.exists():
        logger.info("🔒 SSL Certificate valid (%s). Launching Gunicorn HTTPS server on %s...", cert_file, bind_addr)
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
        logger.info("🔓 No valid SSL Certificate found. Launching Gunicorn HTTP server on %s...", bind_addr)
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


