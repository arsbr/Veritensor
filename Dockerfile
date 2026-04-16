# 1. Main CLI Image
FROM python:3.11-slim-bookworm

# Install system dependencies
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y curl git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
# 2. Cosign    
RUN curl -sL "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign

# --- Install Veritensor ---
WORKDIR /app

# Copy dependency definition from ROOT (removed 'scanner/')
COPY pyproject.toml .

# Create dummy package structure to allow installing dependencies
# before the actual code is copied. This speeds up re-builds.
RUN mkdir -p src/veritensor && touch src/veritensor/__init__.py
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir .

# Copy source code from ROOT (removed 'scanner/')
COPY src/ src/

# Copy config from ROOT
COPY veritensor.yaml .

# Re-install the package to link the actual source code
RUN pip install .

# --- Setup Entrypoint ---
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# The entrypoint script will handle argument parsing
ENTRYPOINT ["/entrypoint.sh"]
