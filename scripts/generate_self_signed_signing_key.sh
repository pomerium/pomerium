#!/bin/bash
# See: https://cloud.google.com/iot/docs/how-tos/credentials/keys#generating_an_es256_key_with_a_self-signed_x509_certificate
# To generate an ES256 key with a self-signed X.509 certificate that expires far in the future, run the following commands:

openssl ecparam \
	-genkey \
	-name prime256v1 \
	-noout \
	-out ec_private.pem

openssl req \
	-x509 \
	-new \
	-key ec_private.pem \
	-days 1000000 \
	-out ec_public.pem \
	-subj "/CN=unused"

# uncomment if you want RSA / RS256
# openssl genpkey -algorithm RSA -out rsa_private.pem -pkeyopt rsa_keygen_bits:2048
# openssl req -x509 -nodes -newkey rsa:2048 -keyout rsa_private.pem -out rsa_cert.pem -subj "/CN=unused"

# uncomment if you want EdDSA / Ed25519
# openssl is /usr/local/opt/openssl/bin/openssl on mac with brew otherwise it is libressl
# openssl genpkey -algorithm ED25519 -out ed25519_private.pem
# openssl req -x509 -new -key ed25519_private.pem -days 1000000 -out ed25519_public.pem -subj "/CN=unused"
