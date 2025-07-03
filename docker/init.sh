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

echo "Start main process"
python -m app.main
