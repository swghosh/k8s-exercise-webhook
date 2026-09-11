#!/bin/bash
# Generate self-signed TLS certificates for the webhook server.
# The certificate SAN must match the Kubernetes Service DNS name.

set -euo pipefail

SERVICE_NAME="image-webhook"
NAMESPACE="image-webhook"
CERT_DIR="certs"

mkdir -p "$CERT_DIR"

# Generate CA key and cert
openssl genrsa -out "$CERT_DIR/ca.key" 2048
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" \
  -subj "/CN=Webhook CA" -days 3650 -out "$CERT_DIR/ca.crt"

# Generate server key
openssl genrsa -out "$CERT_DIR/tls.key" 2048

# Create CSR config with SANs
cat > "$CERT_DIR/csr.conf" <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = ${SERVICE_NAME}.${NAMESPACE}.svc

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
DNS.4 = ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
EOF

# Generate CSR and sign it
openssl req -new -key "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.csr" \
  -config "$CERT_DIR/csr.conf"
openssl x509 -req -in "$CERT_DIR/tls.csr" -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/tls.crt" -days 3650 \
  -extensions v3_req -extfile "$CERT_DIR/csr.conf"

echo ""
echo "Certificates generated in $CERT_DIR/"
echo ""
echo "CA Bundle (base64) for webhook config:"
base64 < "$CERT_DIR/ca.crt" | tr -d '\n'
echo ""
