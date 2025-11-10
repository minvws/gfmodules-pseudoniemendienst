#!/usr/bin/env bash

set -e

APP_PATH="${FASTAPI_CONFIG_PATH:-app.conf}"

echo "➡️ Creating the configuration file"
if [ -e $APP_PATH ]; then
  echo "⚠️ Configuration file already exists. Skipping."
else
  cp app.conf.example $APP_PATH
fi

echo "➡️ Copying the auth_cert.json file"
if [ -e auth_cert.json ]; then
  echo "⚠️ auth_cert_json file already exists. Skipping."
else
  cp auth_cert.json.example auth_cert.json
fi

OPRF_SECRET_KEY_FILE="secrets/oprf-server.key"
if [ ! -s $OPRF_SECRET_KEY_FILE ]; then
  echo "➡️ Generating OPRF secret key"
  python app/generate-oprf-key.py > $OPRF_SECRET_KEY_FILE
else
  echo "⚠️ OPRF secret key already exists. Skipping."
fi

echo "Migrating"
tools/./migrate_db.sh

echo "Start main process"
python -m app.main
