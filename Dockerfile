FROM python:3.9-slim

WORKDIR /app

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install system dependencies for network tools and Python requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping mtr curl \

    && curl -L -o /tmp/speedtest.tgz https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz \
    && tar -xzf /tmp/speedtest.tgz -C /usr/local/bin speedtest \
    && rm -rf /var/lib/apt/lists/* /tmp/speedtest.tgz \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app /app

CMD ["python", "main.py"]
