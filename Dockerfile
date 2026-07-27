FROM python:3.9-alpine

WORKDIR /app

# Copy the full project so editable install can register the `main` module
COPY . /app

# Install system dependencies for network tools, ACME SSL (openssl, curl, socat), and Python requirements
RUN apk add --no-cache iputils mtr openssl curl socat build-base python3-dev linux-headers \
    && pip install --no-cache-dir -r requirements.txt

# Preserve certs directory volume
VOLUME ["/app/certs"]

CMD ["python", "main.py"]
