#!/usr/bin/env bash
set -euo pipefail

# Sinh cặp cert self-signed CHO DEV, có SAN đúng cho localhost/127.0.0.1.
# KHÔNG dùng cho production - production dùng CA thật (Let's Encrypt, ...).

CERT_DIR="${TLSOCKET_CERT_DIR:-certs}"
mkdir -p "$CERT_DIR"

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Đã tạo $CERT_DIR/server.crt + $CERT_DIR/server.key (SAN: localhost, 127.0.0.1)"
