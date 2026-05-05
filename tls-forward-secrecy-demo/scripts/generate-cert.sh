#!/usr/bin/env bash
set -euo pipefail

mkdir -p /workspace/certs

if [[ -f /workspace/certs/server.crt && -f /workspace/certs/server.key ]]; then
  exit 0
fi

openssl req -x509 \
  -newkey rsa:2048 \
  -nodes \
  -keyout /workspace/certs/server.key \
  -out /workspace/certs/server.crt \
  -days 7 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
