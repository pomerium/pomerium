#!/bin/bash

#!/bin/bash
mkdir -p tls
openssl genrsa -out tls/ca.key 4096
openssl req \
    -x509 -new -nodes -sha256 \
    -key tls/ca.key \
    -days 3650 \
    -subj '/O=Redis Test/CN=Pomerium CA' \
    -out tls/ca.crt
openssl genrsa -out tls/redis.key 2048
openssl req \
    -new -sha256 \
    -key tls/redis.key \
    -subj '/O=Redis Test/CN=Server' | \
    openssl x509 \
        -req -sha256 \
        -CA tls/ca.crt \
        -CAkey tls/ca.key \
        -CAserial tls/ca.txt \
        -CAcreateserial \
        -days 3650 \
        -out tls/redis.crt \
        -extensions san \
        -extfile tls/req.conf
openssl dhparam -out tls/redis.dh 2048
