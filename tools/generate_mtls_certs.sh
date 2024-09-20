#!/usr/bin/env bash

RSA_BITSIZE=3076

openssl genrsa -out ca.key $RSA_BITSIZE
openssl req -x509 -new -nodes -key ca.key -subj "/CN=example-ca" -days 3650 -out ca.crt

# Generate OV cert
openssl genrsa -out ov-key.pem $RSA_BITSIZE
openssl req -new -key ov-key.pem -out ov-csr.pem -config openssl-ov.cnf
openssl x509 -req -days 3650 -in ov-csr.pem -signkey ov-key.pem -out ov-cert.pem -extensions v3_ca -extfile openssl-ov.cnf

# Generate EV cert
openssl genrsa -out ev-key.pem $RSA_BITSIZE
openssl req -new -key ev-key.pem -out ev-csr.pem -config openssl-ev.cnf
openssl x509 -req -days 3650 -in ev-csr.pem -signkey ev-key.pem -out ev-cert.pem -extensions v3_ca -extfile openssl-ev.cnf

# Generate UZI Server cert
# todo
