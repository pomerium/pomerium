#!/bin/bash
# https://github.com/square/certstrap
certstrap init --common-name good-ca
certstrap init --common-name bad-ca

# pomerium client cert
certstrap request-cert --common-name pomerium
certstrap sign pomerium --CA good-ca

# downstream app
certstrap request-cert -ip 127.0.0.1 -domain web-app,localhost
certstrap sign web-app --CA good-ca

certstrap request-cert --common-name good-curl
certstrap sign good-curl --CA good-ca

certstrap request-cert --common-name bad-curl
certstrap sign bad-curl --CA bad-ca
