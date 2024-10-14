#!/usr/bin/env bash

set -e

SECRETS_DIR=secrets

echo "Downloading generated certs from secrets container"

for i in {1..3}; do
  response=$(curl --write-out '%{http_code}' --output /dev/null http://secrets/certs/prs/prs.crt)

  if [[ "$response" -eq 200 ]] ; then
    break
  fi

  echo "Attempt $i: Unable to download secrets from secrets container"

  if [[ "$i" -eq 3 ]]; then
    exit 1
  fi

  sleep 5
done

curl -f http://secrets/certs/prs/prs.crt -o $SECRETS_DIR/prs.crt
curl -f http://secrets/certs/prs/prs.key -o $SECRETS_DIR/prs.key
curl -f http://secrets/certs/prs-client-1/prs-client-1.crt -o $SECRETS_DIR/prs-client-1.crt
curl -f http://secrets/certs/prs-client-1/prs-client-1.key -o $SECRETS_DIR/prs-client-1.key
curl -f http://secrets/certs/uzi-server-ca.crt -o $SECRETS_DIR/uzi-server-ca.crt

echo "Downloaded generated certs from secrets container"
