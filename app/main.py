import os
import logging
from pathlib import Path
from app import app, logger, acme_manager, __version__

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
