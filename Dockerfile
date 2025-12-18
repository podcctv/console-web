FROM python:3.9-alpine

WORKDIR /app

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install system dependencies for network tools and Python requirements
# psutil requires compilation, so include build tools and Python headers
RUN apk add --no-cache iputils mtr build-base python3-dev linux-headers \
    && pip install --no-cache-dir -r requirements.txt

# Copy the full project so editable install can register the `main` module
COPY . /app

# Perform an editable install to ensure gunicorn can import `main:app`
RUN pip install --no-cache-dir -e .

CMD ["python", "main.py"]
