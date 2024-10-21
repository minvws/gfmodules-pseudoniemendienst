#!/usr/bin/env bash

set -e

SECRETS_DIR=secrets

mkdir -p $SECRETS_DIR

download() {
  local cert_name=$1
  local crt_url="http://secrets/certs/$cert_name/$cert_name.crt"
  local key_url="http://secrets/certs/$cert_name/$cert_name.key"

  for i in {1..3}; do
    response=$(curl --write-out '%{http_code}' --output /dev/null $crt_url)

    if [[ "$response" -eq 200 ]]; then
      break
    fi

    echo "Attempt $i: Unable to download $cert_name cert from secrets container"

    if [[ "$i" -eq 3 ]]; then
      exit 1
    fi

    sleep 5
  done

  echo "Downloading certificate: $cert_name"
  curl -f $crt_url -o $SECRETS_DIR/$cert_name.crt
  curl -f $key_url -o $SECRETS_DIR/$cert_name.key
}

echo "Downloading generated certs from secrets container"

for cert_name in "$@"; do
  download "$cert_name"
done

curl -f http://secrets/certs/uzi-server-ca.crt -o $SECRETS_DIR/uzi-server-ca.crt

echo "Downloaded generated certs from secrets container"
