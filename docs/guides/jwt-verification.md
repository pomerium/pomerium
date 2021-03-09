---
title: JWT Verification
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy envoy jwt
description: >-
  This example demonstrates how to verify the Pomerium JWT assertion header using Envoy.
---

# JWT Verification
This example demonstrates how to verify the [Pomerium JWT assertion header](https://www.pomerium.io/reference/#pass-identity-headers) using [Envoy](https://www.envoyproxy.io/).

## Requirements
- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [mkcert](https://github.com/FiloSottile/mkcert)

## Overview
Two services are configured in a `docker-compose.yaml` file:

- `pomerium` running an all-in-one deployment of Pomerium on `*.localhost.pomerium.io`
- `envoy-jwt-checker` running envoy with a JWT Authn filter

Once running, the user visits [verify.localhost.pomerium.io](https://verify.localhost.pomerium.io), is authenticated through [authenticate.localhost.pomerium.io](https://authenticate.localhost.pomerium.io), and then the HTTP request is sent to envoy which proxies it to [`verify.pomerium.com`](https://verify.pomerium.com).

Before allowing the request Envoy will verify the signed JWT assertion header using the public key defined by [authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json](https://authenticate.int.example.com/.well-known/pomerium/jwks.json).

## Setup

### 1. Docker Compose
Create a `docker-compose.yaml` file containing:

```yaml
version: "3.8"
services:
  pomerium:
    image: pomerium/pomerium:latest
    ports:
      - "443:443"
    volumes:
      - type: bind
        source: ./cfg/pomerium.yaml
        target: /pomerium/config.yaml
      - type: bind
        source: ./certs/_wildcard.localhost.pomerium.io.pem
        target: /pomerium/_wildcard.localhost.pomerium.io.pem
      - type: bind
        source: ./certs/_wildcard.localhost.pomerium.io-key.pem
        target: /pomerium/_wildcard.localhost.pomerium.io-key.pem

  envoy-jwt-checker:
    image: envoyproxy/envoy:v1.17.1
    ports:
      - "10000:10000"
    volumes:
      - type: bind
        source: ./cfg/envoy.yaml
        target: /etc/envoy/envoy.yaml
```

### 2. Certificates
Using [`mkcert`](https://github.com/FiloSottile/mkcert) generate a certificate for `*.localhost.pomerium.io` in a `certs` directory:

```bash
mkdir certs
cd certs
mkcert '*.localhost.pomerium.io'
```

### 3. Envoy Configuration
Create a `cfg` directory containing the following `envoy.yaml` file:

```yaml
admin:
  access_log_path: /dev/null
  address:
    socket_address: { address: 127.0.0.1, port_value: 9901 }

static_resources:
  listeners:
    - name: ingress-http
      address:
        socket_address: { address: 0.0.0.0, port_value: 10000 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                codec_type: AUTO
                route_config:
                  name: verify
                  virtual_hosts:
                    - name: verify
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: egress-verify
                            auto_host_rewrite: true
                http_filters:
                  - name: envoy.filters.http.jwt_authn
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
                      providers:
                        pomerium:
                          issuer: authenticate.localhost.pomerium.io
                          audiences:
                            - verify.localhost.pomerium.io
                          from_headers:
                            - name: X-Pomerium-Jwt-Assertion
                          remote_jwks:
                            http_uri:
                              uri: https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json
                              cluster: egress-authenticate
                              timeout: 1s
                      rules:
                        - match:
                            prefix: /
                          requires:
                            provider_name: pomerium
                  - name: envoy.filters.http.router
  clusters:
    - name: egress-verify
      connect_timeout: 0.25s
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: verify
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: verify.pomerium.com
                      port_value: 443
      transport_socket:
        name: tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: verify.pomerium.com
    - name: egress-authenticate
      connect_timeout: '0.25s'
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: authenticate
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: pomerium
                      port_value: 443
      transport_socket:
        name: tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: authenticate.localhost.pomerium.io

```

Envoy configuration can be quite verbose, but the crucial bit is the HTTP filter:

```yaml
- name: envoy.filters.http.jwt_authn
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
    providers:
    pomerium:
        issuer: authenticate.localhost.pomerium.io
        audiences:
        - verify.localhost.pomerium.io
        from_headers:
        - name: X-Pomerium-Jwt-Assertion
        remote_jwks:
        http_uri:
            uri: https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json
            cluster: egress-authenticate
            timeout: 1s
    rules:
    - match:
        prefix: /
        requires:
        provider_name: pomerium
```

This configuration pulls the JWT out of the `X-Pomerium-Jwt-Assertion` header, verifies the `iss` and `aud` claims and checks the signature via the public key defined at the `jwks.json` endpoint. Documentation for additional configuration options is available here: [Envoy JWT Authentication](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/jwt_authn_filter#config-http-filters-jwt-authn).

### 4. Pomerium Configuration
Create a `pomerium.yaml` file in the `cfg` directory containing:

```yaml
authenticate_service_url: https://authenticate.localhost.pomerium.io

certificate_file: "/pomerium/_wildcard.localhost.pomerium.io.pem"
certificate_key_file: "/pomerium/_wildcard.localhost.pomerium.io-key.pem"

idp_provider: google
idp_client_id: REPLACE_ME
idp_client_secret: REPLACE_ME

cookie_secret: WwMtDXWaRDMBQCylle8OJ+w4kLIDIGd8W3cB4/zFFtg=
shared_secret: WwMtDXWaRDMBQCylle8OJ+w4kLIDIGd8W3cB4/zFFtg=
signing_key: LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUdxWllpVzJycVo3TUdKTGp4bnNZVWJJcmZxNFdwR044RlgzQVh2UnRjSHdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFYVd1UkNKMjFrL2JvUjNNRytPOVlHQjNXR0R1anVXMHFLVWhucUVwVS9JKzFoZmhuZEJ0WApDZGFpaGVGb0FOWXVCRUp3MFZhRml6QnVZb3l5RVAzOXBRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=

policy:
  - from: https://verify.localhost.pomerium.io
    to: http://envoy-jwt-checker:10000
    allowed_domains:
      - pomerium.com
    pass_identity_headers: true

```

You will need to replace the identity provider credentials for this to work.

## Run
You should now be able to run the example with:

```bash
docker-compose up
```

Visit [verify.localhost.pomerium.io](https://verify.localhost.pomerium.io), login and you see the Pomerium verify page. However, visiting Envoy directly via [localhost:10000](http://localhost:10000) should return a `Jwt is missing` error, thus requiring Pomerium to access Envoy.
