# Stage 1: Base Image
FROM python:3.11-slim-bookworm

# Installing system dependencies (curl is needed to download cosign)
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# --- Installing Cosign (Sigstore) ---
# Download the official release
RUN LATEST_VERSION=$(curl -s https://api.github.com/repos/sigstore/cosign/releases/latest | grep tag_name | cut -d '"' -f 4) && \
    curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" && \
    mv cosign-linux-amd64 /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

# --- Aegis Installation ---
WORKDIR /app

# Copying dependencies
COPY pyproject.toml .
# Creating a fake structure for installing dependencies (caching Docker layers)
RUN mkdir -p src/aegis && touch src/aegis/__init__.py
RUN pip install --no-cache-dir .

# Copy the real code
COPY src/ src/
COPY aegis.yaml .

# Reinstalling the package with the real code
RUN pip install .

# Entry point
ENTRYPOINT ["aegis"]
CMD ["--help"]
