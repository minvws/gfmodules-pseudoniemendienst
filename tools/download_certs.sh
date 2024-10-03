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

curl -f http://secrets/uzi-server-ca.crt -o $SECRETS_DIR/uzi-server-ca.crt
curl -f http://secrets/im1-uzi-server.crt -o $SECRETS_DIR/im1-uzi-server.crt
curl -f http://secrets/im2-uzi-server.crt -o $SECRETS_DIR/im2-uzi-server.crt

curl -f http://secrets/prs.local/prs.local.crt -o $SECRETS_DIR/prs.local.crt
curl -f http://secrets/prs.local/prs.local.key -o $SECRETS_DIR/prs.local.key

curl -f http://secrets/prs-client-1.local/prs-client-1.local.crt -o $SECRETS_DIR/prs-client-1.local.crt
curl -f http://secrets/prs-client-1.local/prs-client-1.local.key -o $SECRETS_DIR/prs-client-1.local.key
curl -f http://secrets/prs-client-2.local/prs-client-2.local.crt -o $SECRETS_DIR/prs-client-2.local.crt
curl -f http://secrets/prs-client-2.local/prs-client-2.local.key -o $SECRETS_DIR/prs-client-2.local.key

echo "Downloaded generated certs from secrets container"
