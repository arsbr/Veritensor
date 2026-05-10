# ==========================================
# STAGE 1: Builder (Compile a pure Cosign)
# ==========================================
FROM golang:1.25-bookworm AS cosign-builder

ENV CGO_ENABLED=0
ENV GOMAXPROCS=2

ARG COSIGN_VERSION=v2.5.3

RUN go install github.com/sigstore/cosign/v2/cmd/cosign@${COSIGN_VERSION}

# Checking embedded dependency versions
RUN go version -m /go/bin/cosign
# ==========================================
# STAGE 2: Main CLI Image
# ==========================================
FROM python:3.11-slim-bookworm

ENV TRIVY_DISABLE_VEX_NOTICE=true

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=cosign-builder /go/bin/cosign /usr/local/bin/cosign


RUN cosign version

# --- Install Veritensor ---
WORKDIR /app

# Copy dependency definition from ROOT
COPY pyproject.toml .

# Create dummy package structure to allow installing dependencies
# before the actual code is copied. This speeds up re-builds.
RUN mkdir -p src/veritensor && touch src/veritensor/__init__.py
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir .

# Copy source code from ROOT
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
