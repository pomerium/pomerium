#!/bin/bash
# Thank you @ https://medium.com/@benjamin.black/how-to-obtain-an-ecdsa-wildcard-certificate-from-lets-encrypt-be217c737cfe
# See also:
#   https://cloud.google.com/iot/docs/how-tos/credentials/keys#generating_an_es256_key_with_a_self-signed_x509_certificate
#   https://community.letsencrypt.org/t/ecc-certificates/46729
#
# Let’s Encrypt currently generates RSA certificates, but not yet ECDSA certificates.
# Support for generating ECDSA certificates is on the horizon, but is not here yet.
# However, Let’s Encrypt does support *signing* ECDSA certificates when presented with a
# Certificate Signing Request. So we can generate the appropriate CSR on the client,
# and send it to Let’s Encrypt using the --csr option of the certbot client for Let’s Encrypt to sign.

# The following generates a NIST P-256 (aka secp256r1 aka prime256v1) EC Key Pair
openssl ecparam \
	-genkey \
	-name prime256v1 \
	-noout \
	-out ec_private.pem

openssl req -x509 -new \
	-key ec_private.pem \
	-days 365 \
	-out ec_public.pem \
	-subj "/CN=unused"

openssl req -new \
	-sha512 \
	-key privkey.pem \
	-nodes \
	-subj "/CN=beyondperimeter.com" \
	-reqexts SAN \
	-extensions SAN \
	-config <(cat /etc/ssl/openssl.cnf <(printf '[SAN]\nsubjectAltName=DNS:*.corp.beyondperimeter.com')) \
	-out csr.pem \
	-outform pem

openssl req -in csr.pem -noout -text

certbot certonly \
	--preferred-challenges dns-01 \
	--work-dir le/work \
	--config-dir le/config \
	--logs-dir le/logs \
	--agree-tos \
	--email bobbydesimone@gmail.com \
	-d *.corp.beyondperimeter.com \
	--csr csr.pem
