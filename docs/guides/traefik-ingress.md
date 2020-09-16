---
title: Traefik Ingress
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy traefik kubernetes forwardauth forward-auth external helm k8s ingress
description: >-
  This guide covers how to use Pomerium to secure Traefik when used as a Kubernetes Ingress Controller
---

# Securing Traefik Ingress

This guide's sources can be found [on github](https://github.com/pomerium/pomerium/tree/master/examples/traefik-ingress).

At the end, you will have an install of a hello-world app proxied by [Traefik](https://containo.us/traefik/) with authorization policy enforced by Pomerium.

This guide specifically demonstrates using Traefik and Pomerium in the context of a [Kubernetes Ingress](https://docs.traefik.io/providers/kubernetes-ingress/) controller, but the patterns can be utilized in anywhere [Traefik is deployed](https://docs.traefik.io/providers/overview/).

## Background

Traefik can be [configured](https://docs.traefik.io/middlewares/forwardauth/) to authorize requests by calling a remote authorization service.  Pomerium is compatible with this protocol and can thus be used to protect services behind Traefik.  In this configuration, Pomerium does not directly proxy traffic, but only performs authorization decisions on behalf of Traefik.  This is useful for integrating into existing load balancer infrastructure.

For more information on using Pomerium as an external authorization endpoint, see [forward auth](https://www.pomerium.com/reference/#forward-auth) in the Pomerium docs.

## How It Works

- Install Traefik as an [Ingress Controller](https://kubernetes.io/docs/concepts/services-networking/ingress/) on your Kubernetes cluster
- Install a standard Pomerium configuration with `forwardauth` enabled
- Create [middleware](https://docs.traefik.io/middlewares/forwardauth/#configuration-examples) to use Pomerium for authorization
- Install an application with an `Ingress` resource configured to use the Pomerium authorization `middleware`
- Pomerium authenticates users via Identity Provider
- Traefik queries Pomerium on each request to verify the traffic is authorized
- Pomerium verifies the traffic against policy, responding to Traefik
- Traefik proxies the traffic or responds with an error

## Pre-requisites

- Access to a Kubernetes cluster 
- Helm (already initialized if using helm v2)
- A copy of the [example repo](https://github.com/pomerium/pomerium/tree/master/examples/traefik-ingress) checked out
- Valid credentials for your OIDC provider
- (Optional) `mkcert` to generate locally trusted certificates

This guide is optimized to run on a local kubernetes install in [Docker Desktop](https://www.docker.com/products/docker-desktop), however the configuration should be easily portable to [minikube](https://kubernetes.io/docs/tutorials/hello-minikube/) or traditional clusters.

If running in minikube or other non-local clusters, you will need to use `kubectl port-forward` to forward traffic from `127.0.0.1:[80,443]` to the Traefik service in Kubernetes, or replace `*.localhost.pomerium.io` references with your own domain.

For the purposes of the guide, all resources are installed inside the namespace `pomerium`.
  
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

To provide your own certificates through another mechanism, please overwrite these files or update the `Ingress` configurations accordingly.

## Configure

### Pomerium

Update `values/pomerium.yaml` with your Identity Provider settings, domain names and policy

<<< @/examples/traefik-ingress/values/pomerium.yaml

### Traefik

Helm chart values:

<<< @/examples/traefik-ingress/values/traefik.yaml

Middleware:

<<< @/examples/traefik-ingress/crds/middleware.yaml

### Hello

Helm chart values:

<<< @/examples/traefik-ingress/values/hello.yaml

## Install 

### Add helm repos

<<< @/examples/traefik-ingress/add_repos.sh

### Install charts and CRDs

<<< @/examples/traefik-ingress/install.sh

After 1-2 minutes, browse to [hello.localhost.pomerium.io](https://hello.localhost.pomerium.io).

You should be prompted to log in through your IdP and then granted access to the deployed `hello` instance.

## That's it!

Your `hello` application is protected by Pomerium
