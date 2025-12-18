FROM python:3.9-alpine

WORKDIR /app

# Copy the full project so editable install can register the `main` module
COPY . /app

# Install system dependencies for network tools and Python requirements
# psutil requires compilation, so include build tools and Python headers
RUN apk add --no-cache iputils mtr build-base python3-dev linux-headers \
    && pip install --no-cache-dir -r requirements.txt

CMD ["python", "main.py"]
