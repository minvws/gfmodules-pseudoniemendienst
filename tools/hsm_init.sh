#!/usr/bin/env bash

# This generates a new token with the label "PRS" and adds some initial keys.
# The keys are named REK-1, BPGK-1. The keys are actually two keys: a AES key for encryption/decryption. And a HMAC key for signing/verifying.

softhsm2-util --init-token --slot 0 --label "PRS" --pin 1234 --so-pin 1234

KEYS="REK-1 BPGK-1"

for label in $KEYS; do
  pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -l --pin 1234 --token "PRS" --keygen --key-type AES:32 --label "${label}-aes"
  pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -l --pin 1234 --token "PRS" --keygen --key-type GENERIC:32 --label "${label}-hmac"
done
