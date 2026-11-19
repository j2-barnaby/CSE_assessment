#!/usr/bin/env bash
# STEP 3: generate a self-signed TLS certificate for local testing.
# ECDSA P-384 key + SHA-384 signature: both NIST-approved (SP 800-52r2 / FIPS 186).
# Accepted risk: self-signed (browser warning). Production would use a
# certificate issued by the organisation's / DoD PKI CA - see POA&M.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs
openssl req -x509 -nodes -days 365 \
  -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
  -sha384 \
  -keyout certs/nginx.key -out certs/nginx.crt \
  -subj "/C=GB/O=Company X/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 certs/nginx.key
chmod 644 certs/nginx.crt
openssl x509 -in certs/nginx.crt -noout -subject -dates -ext subjectAltName
