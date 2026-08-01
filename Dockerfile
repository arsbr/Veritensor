FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .

RUN mkdir -p src/veritensor && touch src/veritensor/__init__.py

# build tools
RUN pip install --no-cache-dir --upgrade \
    pip \
    setuptools>=78.1.1 \
    wheel>=0.46.2

RUN pip install --no-cache-dir .

COPY src/ src/

COPY veritensor.yaml .

RUN pip install --no-cache-dir --no-deps .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
