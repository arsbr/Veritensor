FROM python:3.11-slim-bookworm

# Security updates and cleanup
RUN apt-get update && apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# --- Install Veritensor ---
WORKDIR /app

# Copy dependency definition from ROOT
COPY pyproject.toml .

# Copy source code from ROOT
COPY src/ src/

# Copy config from ROOT
COPY veritensor.yaml .

RUN pip install --no-cache-dir --upgrade pip

# Re-install the package to link the actual source code
RUN pip install --no-cache-dir .

# --- Setup Entrypoint ---
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# The entrypoint script will handle argument parsing
ENTRYPOINT ["/entrypoint.sh"]
