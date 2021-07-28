---
title: Environment Variables
lang: en-US
meta:
    - name: keywords
      content: configuration options settings Pomerium enterprise console
---

# Pomerium Console Environment Variables

The keys listed below can be applied in Pomerium Console's `config.yaml` file, or applied as environment variables (in uppercase, replacing `-` with `_`).

## administrators

a list of user ids, names or emails to make administrators, useful for bootstrapping


**Default value:** `none`

## bind-addr

the address to listen on

**Default value:** `:8701`

## customer-id

the customer id

**Default value:** `none`

## database-encryption-key

base64-encoded encryption key for encrypting sensitive data in the database


**Default value:** `none`

## database-url

the database to connect to

**Default value:** `postgresql://pomerium:pomerium@localhost:5432/dashboard?sslmode=disable
`

## databroker-service-url

the databroker service url

**Default value:** `http://localhost:5443`

## disable-validation

disable config validation

**Default value:** `false`

## enable-remote-diagnostics

enable remote diagnostics

**Default value:** `false`

## grpc-addr

the address to listen for gRPC on

**Default value:** `:8702`

## help

help for serve

**Default value:** `false`

## license

license JWT

**Default value:** `none`

## override-certificate-name

override the certificate name used for the databroker connection


**Default value:** `none`

## prometheus-data-dir

path to prometheus data

**Default value:** `none`

## prometheus-listen-addr

embedded prometheus listen address as host:port

**Default value:** `127.0.0.1:9090`

## prometheus-scrape-interval

prometheus scrape frequency

**Default value:** `10s`

## prometheus-url

url to access prometheus metrics server

**Default value:** `none`

## shared-secret

base64-encoded shared secret for signing JWTs

**Default value:** `none`

## signing-key

base64-encoded signing key (public or private) for verifying JWTs


**Default value:** `none`

## tls-ca

base64-encoded string of tls-ca

**Default value:** `none`

## tls-ca-file

file storing tls-ca

**Default value:** `none`

## tls-cert

base64-encoded string of tls-cert

**Default value:** `none`

## tls-cert-file

file storing tls-cert

**Default value:** `none`

## tls-insecure-skip-verify

disable remote hosts TLS certificate chain and hostname check


**Default value:** `false`

## tls-key

base64-encoded string of tls-key

**Default value:** `none`

## tls-key-file

file storing tls-key

**Default value:** `none`

## use-static-assets

when false, forward static requests to localhost:3000

**Default value:** `true`
