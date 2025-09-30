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
  echo "⚠️ auth_cert.json file already exists. Skipping."
else
  cp auth_cert.json.example auth_cert.json
fi

ensure_secret() {
  local key="$1"
  local default="$2"
  local generator="$3"
  local is_file="$4"   # for file keys like server_key_file

  if ! grep -q "^$key=" "$APP_PATH"; then
    echo "❌ ERROR: $key= entry not found in $APP_PATH"
    exit 1
  fi

  local value=""
  if grep -q "^$key=" "$APP_PATH"; then
    value=$(awk -F= -v k="$key" '$1 == k {gsub(/^ +| +$/, "", $2); print $2}' "$APP_PATH")
  fi

  if [ -z "$value" ]; then
    if [ "$is_file" == "true" ]; then
      if [ -f "$default" ]; then
        value="$default"
        echo "➡️ Found existing $key file at $value, updating app.conf"
      else
        value="$default"
        echo "➡️ Generating $key at default path $value"
        mkdir -p "$(dirname "$value")"
        eval "$generator > \"$value\""
      fi
      if grep -q "^$key=" "$APP_PATH"; then
        sed -i "s|^$key=.*|$key=$value|" "$APP_PATH"
      else
        echo "$key=$value" >> "$APP_PATH"
      fi
    else
      value=$($generator)
      echo "➡️ Generating $key"
      sed -i "s|^$key=.*|$key=$value|" "$APP_PATH"
    fi
  else
    if [ "$is_file" == "true" ]; then
      if [ -f "$value" ]; then
        echo "⚠️ $key already exists at $value. Skipping."
      else
        echo "➡️ Generating $key at $value"
        mkdir -p "$(dirname "$value")"
        eval "$generator > \"$value\""
      fi
    else
      echo "⚠️ $key already exists in app.conf. Skipping."
    fi
  fi
}

# HMAC secret key
ensure_secret "hmac_key" "" "openssl rand -base64 32"

# AES secret key
ensure_secret "aes_key" "" "openssl rand -base64 32"

# OPRF server key file
ensure_secret "server_key_file" "secrets/oprf-server.key" "python app/generate-oprf-key.py" "true"


echo "Migrating"
tools/./migrate_db.sh

echo "Start main process"
python -m app.main
