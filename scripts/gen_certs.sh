#!/usr/bin/env bash
set -euo pipefail

# Sinh cert cho dev: 1 CA cục bộ (ca.key/ca.crt, chỉ tạo 1 lần, KHÔNG sinh
# lại mỗi lần chạy) ký server.crt (CA:FALSE, extendedKeyUsage=serverAuth).
# Client tin ca.crt, không tin trực tiếp server.crt - nên server.crt có
# thể sinh lại bao nhiêu lần cũng được (vd đổi IP LAN) mà không cần gửi
# lại gì cho client, miễn ca.crt không đổi.
# KHÔNG dùng cho production - production dùng CA thật (Let's Encrypt, ...).

CERT_DIR="${TLSOCKET_CERT_DIR:-certs}"
mkdir -p "$CERT_DIR"

SAN="DNS:localhost,IP:127.0.0.1"
if [ -n "${TLSOCKET_LAN_IP:-}" ]; then
  SAN="$SAN,IP:$TLSOCKET_LAN_IP"
fi

if [ ! -f "$CERT_DIR/ca.key" ] || [ ! -f "$CERT_DIR/ca.crt" ]; then
  openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
    -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
    -subj "/CN=TLSocket Dev CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  echo "Đã tạo CA mới: $CERT_DIR/ca.key + $CERT_DIR/ca.crt (giữ nguyên cho các lần sau)"
fi

EXT_FILE="$(mktemp)"
trap 'rm -f "$EXT_FILE"' EXIT
cat > "$EXT_FILE" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SAN
EOF

openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
  -subj "/CN=localhost"

openssl x509 -req -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/server.crt" -days 365 \
  -extfile "$EXT_FILE"

rm -f "$CERT_DIR/server.csr"

echo "Đã tạo $CERT_DIR/server.crt + $CERT_DIR/server.key, ký bởi $CERT_DIR/ca.crt (SAN: $SAN)"
