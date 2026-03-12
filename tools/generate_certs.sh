#!/usr/bin/env bash

set -e

SECRETS_DIR=secrets
RSA_BITSIZE=3076

echo "Generating certificates"

SERVER_EXTFILE="$SECRETS_DIR/prs.local.ext"

# Generate CA certificate
echo "Generating CA certificate..."
openssl genrsa -out $SECRETS_DIR/uzi-server-ca.key $RSA_BITSIZE
openssl req -x509 -new -nodes -key $SECRETS_DIR/uzi-server-ca.key -subj "/CN=uzi-server-ca" -days 3650 -sha256 -out $SECRETS_DIR/uzi-server-ca.crt \
	-addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-addext "subjectKeyIdentifier=hash"

# Generate server certificate
echo "Generating server certificate..."
openssl genrsa -out $SECRETS_DIR/prs.local.key $RSA_BITSIZE
openssl req -new -key $SECRETS_DIR/prs.local.key -subj "/CN=prs.local" -out $SECRETS_DIR/prs.local.csr
cat > "$SERVER_EXTFILE" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:prs,DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in $SECRETS_DIR/prs.local.csr -CA $SECRETS_DIR/uzi-server-ca.crt -CAkey $SECRETS_DIR/uzi-server-ca.key -CAcreateserial -out $SECRETS_DIR/prs.local.crt -days 365 -sha256 -extfile "$SERVER_EXTFILE"

# Cleanup temporary files
rm -f $SECRETS_DIR/prs.local.csr $SECRETS_DIR/uzi-server-ca.srl "$SERVER_EXTFILE"

echo "Certificates generated successfully"
