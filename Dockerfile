FROM python:3.9-alpine

WORKDIR /app

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install system dependencies for network tools and Python requirements
RUN apk add --no-cache iputils mtr \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app /app

CMD ["python", "main.py"]
