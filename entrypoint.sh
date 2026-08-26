#!/bin/sh
set -e

# Run auto init check
python -c "import app.acme_manager as am; am._auto_init()" || true

# Check if valid SSL certificate exists
if python -c "import app.acme_manager as am; exit(0 if am._cert_is_valid(min_days=1) else 1)" 2>/dev/null; then
    CERT_FILE="/app/certs/cert.pem"
    if [ -f "/app/certs/fullchain.pem" ]; then
        CERT_FILE="/app/certs/fullchain.pem"
    fi
    echo "🔒 SSL Certificate present and valid ($CERT_FILE). Starting Gunicorn HTTPS on 0.0.0.0:8080..."
    exec gunicorn -b 0.0.0.0:8080 --certfile "$CERT_FILE" --keyfile /app/certs/key.pem --workers 2 --timeout 120 app.main:app
else
    python -c "import app.acme_manager as am; am.remove_cert_files()" 2>/dev/null || true
    echo "🔓 No valid SSL Certificate found. Starting Gunicorn HTTP on 0.0.0.0:8080..."
    exec gunicorn -b 0.0.0.0:8080 --workers 2 --timeout 120 app.main:app
fi

