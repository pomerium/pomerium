---
title: Nginx
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy nginx
description: >-
  This guide covers how to use Pomerium to protect services behind an nginx
  proxy.
---

# Securing Nginx

This recipe's sources can be found [on github](https://github.com/pomerium/pomerium/tree/master/examples/nginx)

At the end, you will have a locally running install of [httpbin](https://httpbin.org/) behind nginx with policy enforced by Pomerium.

## Background

Nginx can be [configured](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/) to authorize requests by calling an external authorization service. Pomerium is compatible with this external authentication protocol and can thus be used to protect services behind nginx. In this configuration, Pomerium does not proxy traffic, but authorizes it on behalf of nginx. This is useful for integrating into existing load balancer infrastructure.

For more information on using Pomerium as an external authorization endpoint, see [forward auth](https://www.pomerium.com/reference/#forward-auth) in the Pomerium docs.

## How It Works

- Create a standard pomerium configuration to authenticate against your identity provider (IdP)
- Configure nginx to authorize incoming requests via pomerium
- Pomerium authenticates users via IdP
- Nginx queries Pomerium on each request to verify the traffic is authorized
- Pomerium verifies the traffic against policy, responding to nginx
- Nginx proxies the traffic or responds with an error

## Pre-requisites

This recipe is designed to run on a local docker-compose instance. The included configuration can be adopted for any nginx deployment.

- docker
- docker-compose
- A copy of the [example repo](https://github.com/pomerium/pomerium/tree/master/examples/nginx) checked out
- Valid credentials for your OIDC provider
- (Optional) `mkcert` to generate locally trusted certificates

## Certificates (optional)

This demo comes with its own certificates, but they will generate warnings in your browser. You may instead provide your own or use [mkcert](https://github.com/FiloSottile/mkcert) to generate locally trusted certificates.

After installing `mkcert`, run the following inside the example repo:

```bash
mkcert -install
   mkcert '*.localhost.pomerium.io'
```

This will install a trusted CA and generate a new wildcard certificate:

- `_wildcard.localhost.pomerium.io.pem`
- `_wildcard.localhost.pomerium.io-key.pem`

To provide your own certificates through another mechanism, please overwrite these files or update `docker-compose.yaml` accordingly.

## Configure

### Pomerium

Update `config.yaml` with your IdP settings and desired policy

<<< @/examples/nginx/config.yaml

### Nginx - pomerium

Nginx configuration for Pomerium endpoints

<<< @/examples/nginx/pomerium.conf

### Nginx - httpbin

Nginx configuration for the protected endpoint

<<< @/examples/nginx/httpbin.conf

### Docker Compose

<<< @/examples/nginx/docker-compose.yaml

Run `docker-compose up`. After a few seconds, browse to [httpbin.localhost.pomerium.io](https://httpbin.localhost.pomerium.io).

You should be prompted to log in through your IdP and then granted access to the deployed `httpbin` instance.

## That's it!

Your `httpbin` install is protected by Pomerium.

## Adapting

To re-use the configuration in this demo in other contexts:

- Update `httpbin.conf` to reflect the correct forward auth URL in `location @error401`
- Update `pomerium.conf` to reflect the pomerium hostname(s) or IP(s) in `upstream pomerium`
- Update `pomerium.conf` to reflect your pomerium authenticate and forward auth hostnames in `server_name`
