#!/usr/bin/env bash

set -e

APP_PATH="${FASTAPI_CONFIG_PATH:-app.conf}"

# where default config file is coming from
APP_CONFIG_TEMPLATE_PATH="${APP_CONFIG_TEMPLATE_PATH:-app.conf.example}"

echo "➡️ Creating the configuration file"
if [ -e $APP_PATH ]; then
  echo "⚠️ Configuration file already exists. Skipping."
else
  cp $APP_CONFIG_TEMPLATE_PATH $APP_PATH

  MASTER_KEY="$(openssl rand -base64 32)"

  sed -i "s|^\(master_key=\).*|\1$MASTER_KEY|" "$APP_PATH"
fi

OPRF_SECRET_KEY_FILE="secrets/oprf-server.key"
if [ ! -s $OPRF_SECRET_KEY_FILE ]; then
  echo "➡️ Generating OPRF secret key"
  python app/generate-oprf-key.py >$OPRF_SECRET_KEY_FILE
else
  echo "⚠️ OPRF secret key already exists. Skipping."
fi

echo "Migrating"
tools/./migrate_db.sh

echo "Start main process"
python -m app.main
