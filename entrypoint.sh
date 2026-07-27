#!/bin/sh
set -e

python -c "import app.acme_manager as am; am._auto_init()"

if [ -f "/app/certs/cert.pem" ] && [ -f "/app/certs/key.pem" ]; then
    CERT_FILE="/app/certs/cert.pem"
    if [ -f "/app/certs/fullchain.pem" ]; then
        CERT_FILE="/app/certs/fullchain.pem"
    fi
    echo "🔒 SSL Certificate present ($CERT_FILE). Starting Gunicorn HTTPS on 0.0.0.0:8080..."
    exec gunicorn -b 0.0.0.0:8080 --certfile "$CERT_FILE" --keyfile /app/certs/key.pem --workers 2 --timeout 120 app.main:app
else
    echo "🔓 No SSL Certificate found yet. Starting Gunicorn HTTP on 0.0.0.0:8080..."
    exec gunicorn -b 0.0.0.0:8080 --workers 2 --timeout 120 app.main:app
fi
