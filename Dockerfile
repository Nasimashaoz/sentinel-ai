FROM python:3.11-slim

LABEL maintainer="Nasima Shaoz <github.com/Nasimashaoz>"
LABEL description="Sentinel AI — 24/7 Self-Hosted AI Security Agent"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    procps \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directory
RUN mkdir -p /app/data

CMD ["python", "sentinel.py"]
