FROM python:3.11-slim-bookworm

# Security updates and cleanup
RUN apt-get update && apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# --- Install Veritensor ---
WORKDIR /app

# Copy dependency definition from ROOT
COPY pyproject.toml .

# Create dummy package structure to allow installing dependencies
# before the actual code is copied. This speeds up re-builds.
RUN mkdir -p src/veritensor && touch src/veritensor/__init__.py
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir "msgpack>=1.2.1" "setuptools>=78.1.1"
RUN pip install --no-cache-dir .

# Copy source code from ROOT
COPY src/ src/

# Copy config from ROOT
COPY veritensor.yaml .

# Re-install the package to link the actual source code
RUN pip install --no-cache-dir --no-deps .

# --- Setup Entrypoint ---
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# The entrypoint script will handle argument parsing
ENTRYPOINT ["/entrypoint.sh"]
