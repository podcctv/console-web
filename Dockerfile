FROM python:3.9-slim

WORKDIR /app

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install system dependencies for network tools and Python requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping mtr curl \
    && curl -s https://install.speedtest.net/app/cli/install.deb.sh | bash \
    && apt-get install -y --no-install-recommends speedtest \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app /app

CMD ["python", "main.py"]
