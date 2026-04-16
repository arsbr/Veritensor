# ==========================================
# STAGE 1: Builder (Компилируем чистый Cosign)
# ==========================================
# Используем свежий Go 1.26 на базе Debian (Bookworm), чтобы избежать CVE и ошибок Alpine
FROM golang:1.26-bookworm AS cosign-builder

# Отключаем CGO для создания статичного бинарника и ограничиваем потоки, чтобы не убить CI/CD по памяти
ENV CGO_ENABLED=0
ENV GOMAXPROCS=2

# Компилируем Cosign из исходников. 
# Так как мы используем Go 1.26, в бинарнике НЕ БУДЕТ старых уязвимостей!
RUN go install github.com/sigstore/cosign/v2/cmd/cosign@latest


# ==========================================
# STAGE 2: Main CLI Image
# ==========================================
FROM python:3.11-slim-bookworm

# Устанавливаем системные зависимости
# (curl и git больше не нужны, так как мы не качаем Cosign из интернета!)
RUN apt-get update && apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Копируем свежесобранный, безопасный бинарник Cosign из первой стадии
COPY --from=cosign-builder /go/bin/cosign /usr/local/bin/cosign

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
