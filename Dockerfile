FROM python:3.9-alpine

WORKDIR /app

# Install system dependencies for network tools, ACME SSL (openssl, curl, socat, git, ca-certificates)
RUN apk add --no-cache iputils mtr openssl curl socat git ca-certificates bind-tools build-base python3-dev linux-headers \
    && (git clone --depth 1 https://github.com/acmesh-official/acme.sh.git /tmp/acme-src || git clone --depth 1 https://gitee.com/neilpang/acme.sh.git /tmp/acme-src) \
    && cd /tmp/acme-src \
    && ./acme.sh --install --home /root/.acme.sh --config-home /root/.acme.sh \
    && ln -s /root/.acme.sh/acme.sh /usr/local/bin/acme.sh \
    && rm -rf /tmp/acme-src

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x /app/entrypoint.sh

# Preserve certs volume
VOLUME ["/app/certs"]

CMD ["/bin/sh", "/app/entrypoint.sh"]
