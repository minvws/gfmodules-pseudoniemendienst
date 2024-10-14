#!/usr/bin/env bash

set -e

echo "➡️ Generating TLS certificates"
if [ -e secrets/ssl/server.key ] && [ -e secrets/ssl/server.cert ]; then
    echo "⚠️ TLS certificates already exist. Skipping."
else
    ./tools/download_certs.sh
    ./tools/generate_certs.sh
fi

echo "➡️ Creating the configuration file"
if [ -e app.conf ]; then
    echo "⚠️ Configuration file already exists. Skipping."
else
    cp app.conf.autopilot app.conf
fi

echo "➡️ Copying the auth_cert.json file"
if [ -e auth_cert.json ]; then
    echo "⚠️ auth_cert_json file already exists. Skipping."
else
    cp auth_cert.json.example auth_cert.json
fi

echo "Start main process"
python -m app.main
