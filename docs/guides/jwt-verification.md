---
title: JWT Verification
lang: en-US
meta:
  - name: keywords
    content: pomerium, identity access proxy, envoy, jwt,
description: >-
  This example demonstrates how to verify the Pomerium JWT assertion header using Envoy.
---

# JWT Verification
This example demonstrates how to verify the [Pomerium JWT assertion header](https://www.pomerium.io/reference/#pass-identity-headers) using [Envoy](https://www.envoyproxy.io/). This is useful for legacy or 3rd party applications which can't be modified to perform verification themselves.

This guide is a practical demonstration of some of the topics discussed in [Mutual Authentication: A Component of Zero Trust].

## Requirements
- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [mkcert](https://github.com/FiloSottile/mkcert)

This guide assumes you already have a working IdP connection to provide user data. See our [Identity Provider](/docs/identity-providers/readme.md) docs for more information.

## Overview
Three services are configured in a `docker-compose.yaml` file:

- `pomerium` running an all-in-one deployment of Pomerium on `*.localhost.pomerium.io`
- `envoy-jwt-checker` running envoy with a JWT Authn filter
- `httpbin` as our example legacy application without JWT verifivation.

In our Docker Compose configuration we'll define two networks. `pomerium` and `envoy-jwt-checker` will be on the `frontend` network, simulating your local area network (**LAN**). `envoy-jwt-checker` will also be on the `backend` network, along with `httpbin`. This means that `envoy-jwt-checker` is the only other service that can communicate with `httpbin`.

For a detailed explanation of this security model, see [Mutual Authentication With a Sidecar]

Once running, the user visits [verify.localhost.pomerium.io], is authenticated through [authenticate.localhost.pomerium.io], and then the HTTP request is sent to envoy which proxies it to the httpbin app.

Before allowing the request Envoy will verify the signed JWT assertion header using the public key defined by `authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json`.

## Setup

The configuration presented here assumes a working route to the domain space `*.localhost.pomerium.io`. You can make entries in your `hosts` file for the domains used, or change this value to match your local environment.

::: tip
Mac and Linux users can use DNSMasq to map the `*.localhost.pomerium.io` domain (including all subdomains) to a specified test address:

- [Local Development with Wildcard DNS] (macOS)
- [Local Development with Wildcard DNS on Linux]
:::

1. Create a `docker-compose.yaml` file containing:

    ```yaml
    version: "3.9"
    networks:
      frontend:
        driver: "bridge"
      backend:
        driver: "bridge"
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
        networks:
          - frontend

      envoy-jwt-checker:
        image: envoyproxy/envoy:v1.17.1
        ports:
          - "10000:10000"
        volumes:
          - type: bind
            source: ./cfg/envoy.yaml
            target: /etc/envoy/envoy.yaml
        networks:
          frontend:
            aliases:
              - "httpbin-sidecar"
          backend:

      httpbin:
        image: kennethreitz/httpbin
        ports:
          - "80:80"
        networks:
          - backend
    ```

1. Using [`mkcert`](https://github.com/FiloSottile/mkcert), generate a certificate for `*.localhost.pomerium.io` in a `certs` directory:

    ```bash
    mkdir certs
    cd certs
    mkcert '*.localhost.pomerium.io'
    ```

1. Create a `cfg` directory containing the following `envoy.yaml` file. Envoy configuration can be quite verbose, but the crucial bit is the HTTP filter (highlighted below):

    ```yaml{30-49}
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
                        - name: httpbin
                          domains: ["httpbin-sidecar"]
                          routes:
                            - match:
                                prefix: "/"
                              route:
                                cluster: egress-httpbin
                                auto_host_rewrite: true
                    http_filters:
                      - name: envoy.filters.http.jwt_authn
                        typed_config:
                          "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
                          providers:
                            pomerium:
                              issuer: authenticate.localhost.pomerium.io
                              audiences:
                                - httpbin.localhost.pomerium.io
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
        - name: egress-httpbin
          connect_timeout: 0.25s
          type: STRICT_DNS
          lb_policy: ROUND_ROBIN
          load_assignment:
            cluster_name: httpbin
            endpoints:
              - lb_endpoints:
                  - endpoint:
                      address:
                        socket_address:
                          address: httpbin
                          port_value: 80
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

    This configuration pulls the JWT out of the `X-Pomerium-Jwt-Assertion` header, verifies the `iss` and `aud` claims and checks the signature via the public key defined at the `jwks.json` endpoint. Documentation for additional configuration options is available here: [Envoy JWT Authentication](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/jwt_authn_filter#config-http-filters-jwt-authn).

1. Create a `pomerium.yaml` file in the `cfg` directory containing:

    ```yaml
    authenticate_service_url: https://authenticate.localhost.pomerium.io

    certificate_file: "/pomerium/_wildcard.localhost.pomerium.io.pem"
    certificate_key_file: "/pomerium/_wildcard.localhost.pomerium.io-key.pem"

    idp_provider: google
    idp_client_id: REPLACE_ME
    idp_client_secret: REPLACE_ME

    cookie_secret: REPLACE_ME
    shared_secret: REPLACE_ME
    signing_key: REPLACE_ME

    routes:
      - from: https://httpbin.localhost.pomerium.io
        to: http://httpbin-sidecar:10000
        pass_identity_headers: true
        policy:
          - allow:
              or:
                - domain:
                    is: example.com
    ```

Replace the identity provider credentials, secrets, and signing key. Adjust the policy to match your configuration.

## Run

You should now be able to run the example with:

1. Turn on the example configuration in Docker:

    ```bash
    docker-compose up
    ```

1. Visit [httpbin.localhost.pomerium.io](https://httpbin.localhost.pomerium.io). Login and you will be redirected to the httpbin page.

1. In this network configuration you cannot access `httpbin` directly. However, visiting Envoy directly via [localhost.pomerium.io:10000/](http://localhost.pomerium.io:10000/) will return a `Jwt is missing` error, confirming that you must authenticate with Pomerium to access Envoy, and any services accessible through it.

[authenticate.localhost.pomerium.io]: https://authenticate.localhost.pomerium.io
[httpbin.localhost.pomerium.io]: https://verify.localhost.pomerium.io
[Local Development with Wildcard DNS on Linux]: https://sixfeetup.com/blog/local-development-with-wildcard-dns-on-linux
[Local Development with Wildcard DNS]: https://blog.thesparktree.com/local-development-with-wildcard-dns
[Mutual Authentication: A Component of Zero Trust]: /docs/topics/mutual-auth.md
[Mutual Authentication With a Sidecar]: /docs/topics/mutual-auth.md#mutual-authentication-with-a-sidecar
[verify.localhost.pomerium.io]: https://verify.localhost.pomerium.io