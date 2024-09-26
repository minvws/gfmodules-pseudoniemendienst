#!/usr/bin/env bash

set -e

SECRETS_DIR=secrets

echo "Generating certs"

RSA_BITSIZE=3076
openssl genrsa -out $SECRETS_DIR/cert-ca.key $RSA_BITSIZE
openssl req -x509 -new -nodes -key $SECRETS_DIR/cert-ca.key -subj "/CN=prs-ca" -days 3650 -out $SECRETS_DIR/cert-ca.crt

# Generate OV cert
openssl genrsa -out $SECRETS_DIR/prs-ov.key $RSA_BITSIZE
openssl req -new -key $SECRETS_DIR/prs-ov.key -out $SECRETS_DIR/prs-ov.csr -config ./tools/openssl-ov.cnf
openssl x509 -req -in $SECRETS_DIR/prs-ov.csr -CA $SECRETS_DIR/cert-ca.crt -CAkey $SECRETS_DIR/cert-ca.key -CAcreateserial -out $SECRETS_DIR/prs-ov.crt -days 365 -sha256

# Generate EV cert
openssl genrsa -out $SECRETS_DIR/prs-ev.key $RSA_BITSIZE
openssl req -new -key $SECRETS_DIR/prs-ev.key -out $SECRETS_DIR/prs-ev.csr -config ./tools/openssl-ev.cnf
openssl x509 -req -in $SECRETS_DIR/prs-ev.csr -CA $SECRETS_DIR/cert-ca.crt -CAkey $SECRETS_DIR/cert-ca.key -CAcreateserial -out $SECRETS_DIR/prs-ev.crt -days 365 -sha256
