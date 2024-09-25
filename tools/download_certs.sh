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

curl -f http://secrets/prs/prs.crt -o $SECRETS_DIR/prs.crt
curl -f http://secrets/prs/prs.key -o $SECRETS_DIR/prs.key
curl -f http://secrets/prs-client-1/prs-client-1.crt -o $SECRETS_DIR/prs-client-1.crt
curl -f http://secrets/prs-client-1/prs-client-1.key -o $SECRETS_DIR/prs-client-1.key
curl -f http://secrets/prs-client-2/prs-client-2.crt -o $SECRETS_DIR/prs-client-2.crt
curl -f http://secrets/prs-client-2/prs-client-2.key -o $SECRETS_DIR/prs-client-2.key
curl -f http://secrets/uzi-server-ca.crt -o $SECRETS_DIR/uzi-server-ca.crt

echo "Downloaded generated certs from secrets container"
