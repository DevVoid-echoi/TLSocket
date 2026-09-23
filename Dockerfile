# Dev/demo image for tlsocket - not hardened for production use.
FROM python:3.12-slim

WORKDIR /app

# Only copy dependency metadata first so `pip install` is cached across
# rebuilds that only change application code.
COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts/healthcheck.py ./scripts/healthcheck.py
RUN pip install --no-cache-dir .

# Runtime file locations (see src/tlsocket/config.py) default to the project
# root; inside the container that's /app.
ENV TLSOCKET_HOST=0.0.0.0 \
    TLSOCKET_PORT=9999 \
    TLSOCKET_METRICS_PORT=9100

# Self-signed dev cert, generated at build time so the image runs standalone.
# See scripts/gen_certs.sh - production must mount/replace certs/ with a
# certificate from a real CA instead.
RUN apt-get update && apt-get install --no-install-recommends -y openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p certs data logs \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
         -keyout certs/server.key -out certs/server.crt \
         -subj "/CN=localhost" \
         -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

EXPOSE 9999 9100

HEALTHCHECK --interval=10s --timeout=3s --retries=3 --start-period=5s \
    CMD python3 scripts/healthcheck.py
CMD ["tlsocket-server"]
