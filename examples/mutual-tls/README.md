# Mutual Authenticated TLS Example

A tiny go http server that enforces client certificates and can be used to test mutual TLS with Pomerium.

## TL;DR

### Pomerium config

```yaml
# See detailed configuration settings : https://www.pomerium.io/reference/
authenticate_service_url: https://authenticate.corp.domain.example
authorize_service_url: https://authorize.corp.domain.example

# identity provider settings : https://www.pomerium.com/docs/identity-providers.html
idp_provider: google
idp_client_id: REPLACE_ME
idp_client_secret: REPLACE_ME

policy:
  - from: https://mtls.corp.domain.example
    to: https://localhost:8443
    allowed_domains:
      - domain.example
    tls_custom_ca_file: "/Users/bdd/examples/mutual-tls/out/good-ca.crt"
    tls_client_cert_file: "/Users/bdd/examples/mutual-tls/out/pomerium.crt"
    tls_client_key_file: "/Users/bdd/examples/mutual-tls/out/pomerium.key"

  - from: https://verify.corp.domain.example
    to: https://verify.pomerium.com
    allow_public_unauthenticated_access: true
```

### Docker-compose

```yaml
version: "3"
services:
  pomerium:
    image: pomerium/pomerium:latest
    environment:
      - CERTIFICATE
      - CERTIFICATE_KEY
      - COOKIE_SECRET
    volumes:
      # Mount your config file : https://www.pomerium.io/reference/
      # be sure to change the default values :)
      - ./example.config.yaml:/pomerium/config.yaml:ro
    ports:
      - 443:443

  mtls:
    image: pomerium/examples:mtls
    environment:
      - TLS_CERT
      - TLS_KEY
      - CLIENT_CA
    ports:
      - 8443:8443
```

## Generate some certificates

This can be done a myriad of ways. The easiest for testing is probably using [certstrap](https://github.com/square/certstrap).

See [scripts/generate_certs.sh](scripts/generate_certs.sh)

## Run the server

Certificates can be set using the following base 64 encoded [environmental variables](env). For example,

```bash
source ./env && go run main.go
```

## Test the server with curl

See [scripts/curl.sh](scripts/curl.sh)

## Docker

Pull `pomerium/examples:mtls` or see [Dockerfile](Dockerfile)

## Configuring Pomerium

See [example.config.yaml](example.config.yaml)
