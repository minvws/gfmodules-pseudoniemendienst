#!/usr/bin/env bash

set -e

SECRETS_DIR=secrets

echo "Downloading generated certs from secrets container"

response=$(curl --write-out '%{http_code}' --output /dev/null http://secrets/README.md)

if [[ "$response" -ne 200 ]] ; then
  echo "Unable to download secrets from secrets container"
  echo "Did you start the docker compose project from the coordination repo?"
  exit 1
fi

curl -f http://secrets/prs/prs.crt -o $SECRETS_DIR/prs-uzi.crt
curl -f http://secrets/prs/prs.key -o $SECRETS_DIR/prs-uzi.key
curl -f http://secrets/uzi-server-ca.crt -o $SECRETS_DIR/uzi-server-ca.crt

echo "Downloaded generated certs from secrets container"


RSA_BITSIZE=3076
openssl genrsa -out $SECRETS_DIR/cert-ca.key $RSA_BITSIZE
openssl req -x509 -new -nodes -key $SECRETS_DIR/cert-ca.key -subj "/CN=example-ca" -days 3650 -out $SECRETS_DIR/cert-ca.crt
# Generate OV cert
openssl genrsa -out $SECRETS_DIR/prs-ov.key $RSA_BITSIZE
openssl req -new -key $SECRETS_DIR/prs-ov.key -out $SECRETS_DIR/prs-ov.csr -config ./tools/openssl-ov.cnf
openssl x509 -req -days 3650 -in $SECRETS_DIR/prs-ov.csr -signkey $SECRETS_DIR/prs-ov.key -out $SECRETS_DIR/prs-ov.crt -extensions v3_ca -extfile ./tools/openssl-ov.cnf
# Generate EV cert
openssl genrsa -out $SECRETS_DIR/prs-ev.key $RSA_BITSIZE
openssl req -new -key $SECRETS_DIR/prs-ev.key -out $SECRETS_DIR/prs-ev.csr -config ./tools/openssl-ev.cnf
openssl x509 -req -days 3650 -in $SECRETS_DIR/prs-ev.csr -signkey $SECRETS_DIR/prs-ev.key -out $SECRETS_DIR/prs-ev.crt -extensions v3_ca -extfile ./tools/openssl-ev.cnf
