---
title: Examples
lang: en-US
sidebarDepth: 2
meta:
  - name: keywords
    content: pomerium community help bugs updates features
description: >-
  This document describes how you users can stay up to date with pomerium,
  report issues, get help, and suggest new features.
---

# Examples

A collection of copy-and-paste-able configurations for various types of clouds, use-cases, and deployments. These files can also be found in the git repository in the `docs/configuration/examples/` directory.

:::tip

Remember to set your identity provider settings and to generate new secret keys!

:::

[[toc]]

## Settings

### Configuration File

<<< @/docs/configuration/examples/config/config.example.yaml

### Environmental Variables

<<< @/docs/configuration/examples/config/config.example.env

## Binary

- Suitable for bare-metal and virtual-machines
- No docker, docker-compose, or kubernetes required
- Minimal configuration
- Pomerium services are run in "all-in-one" mode
- No load balancer required
- Great for testing Pomerium
- Routes default to hosted version of httpbin.org

Customize for your identity provider and run `./bin/pomerium -config config.yaml`

## Docker

Uses the [latest pomerium build](https://hub.docker.com/r/pomerium/pomerium) from docker hub. Docker and docker-compose are great tools for standing up and testing multiple service, and containers without having to stand-up a full on cluster.

### All-in-One

- Minimal container-based configuration.
- Docker and Docker-Compose based.
- Runs a single container for all pomerium services
- Routes default to on-premise [httpbin].

Customize for your identity provider run `docker-compose up -f basic.docker-compose.yml`

#### basic.docker-compose.yml

<<< @/docs/configuration/examples/docker/basic.docker-compose.yml

### Distinct Services

- Docker and Docker-Compose based.
- Uses pre-configured built-in nginx load balancer
- Runs separate containers for each service
- Routes default to on-premise [helloworld], and [httpbin].

Customize for your identity provider run `docker-compose up -f nginx.docker-compose.yml`

#### nginx.docker-compose.yml

<<< @/docs/configuration/examples/docker/nginx.docker-compose.yml

## Helm

- HTTPS (TLS) between client, load balancer, and services
- gRPC requests are routed behind the load balancer
- Routes default to hosted version of httpbin.org
- Includes installer script
- Pomerium serves on HTTPS and your ingress controller may need an annotation to
  connect properly

### GKE

- Uses Google Kubernetes Engine's built-in ingress to do [HTTPS load balancing]

<<< @/docs/configuration/examples/helm/helm_gke.sh

### Kubernetes

- Uses Google Kubernetes Engine's built-in ingress to do [HTTPS load balancing]
- HTTPS (TLS) between client, load balancer, and services
- gRPC requests are routed behind the load balancer
- Routes default to hosted version of httpbin.org
- Includes installer script

#### kubernetes_gke

<<< @/docs/configuration/examples/kubernetes/kubernetes_gke.sh

#### kubernetes-config.yaml

<<< @/docs/configuration/examples/kubernetes/kubernetes-config.yaml

#### pomerium-authenticate.yml

<<< @/docs/configuration/examples/kubernetes/pomerium-authenticate.yml

#### pomerium-authorize.yml

<<< @/docs/configuration/examples/kubernetes/pomerium-authorize.yml

#### pomerium-proxy.yml

<<< @/docs/configuration/examples/kubernetes/pomerium-proxy.yml

#### pomerium-cache.yml

<<< @/docs/configuration/examples/kubernetes/pomerium-cache.yml


#### ingress.yml

<<< @/docs/configuration/examples/kubernetes/ingress.yml

[helloworld]: https://hub.docker.com/r/tutum/hello-world
[httpbin]: https://httpbin.org/
[https load balancing]: https://cloud.google.com/kubernetes-engine/docs/concepts/ingress

## Istio

[istio]: https://github.com/istio/istio
[certmanager]: https://github.com/jetstack/cert-manager
[grafana]: https://github.com/grafana/grafana

- Istio provides mutual TLS via sidecars and to make Istio play well with Pomerium we need to disable TLS on the Pomerium side.
- We need to provide Istio with information on how to route requests via Pomerium to their destinations.
- The following example shows how to make Grafana's [auth proxy](https://grafana.com/docs/grafana/latest/auth/auth-proxy) work with Pomerium inside of an Istio mesh.

#### Gateway

We are using the standard istio-ingressgateway that comes configured with Istio and attach a Gateway to it that deals with a subset of our ingress traffic based on the Host header (in this case `*.yourcompany.com`). This is the Gateway to which we will later attach VirtualServices for more granular routing decisions. Along with the Gateway, because we care about TLS, we are using Certmanager to provision a self-signed certificate (see Certmanager [docs](https://cert-manager.io/docs) for setup instructions).

<<< @/docs/configuration/examples/kubernetes/istio/gateway.yml

#### Virtual Services

Here we are configuring two Virtual Services. One to route from the Gateway to the Authenticate service and one to route from the Gateway to the Pomerium Proxy, which will route the request to Grafana according to the configured Pomerium policy.

<<< @/docs/configuration/examples/kubernetes/istio/virtual-services.yml

#### Service Entry

If you are enforcing mutual TLS in your service mesh you will need to add a ServiceEntry for your identity provider so that Istio knows not to expect a mutual TLS connection with, for example `https://yourcompany.okta.com`.

<<< @/docs/configuration/examples/kubernetes/istio/service-entry.yml

#### Pomerium Configuration

For this example we're using the Pomerium Helm chart with the following `values.yaml` file. Things to note here are the `insecure` flag, where we are disabling TLS in Pomerium in favor of the Istio-provided TLS via sidecars. Also note the `extaEnv` arguments where we are asking Pomerium to extract the email property from the JWT and pass it on to Grafana in a header called `X-Pomerium-Claim-Email`. We need to do this because Grafana does not know how to read the Pomerium JWT but its auth-proxy authentication method can be configured to read user information from headers. The policy document contains a single route that will send all requests with a host header of `https://grafana.yourcompany.com` to the Grafana instance running in the monitoring namespace. We disable ingress because we are using the Istio ingressgateway for ingress traffic and don't need the Pomerium helm chart to create ingress objects for us.

<<< @/docs/configuration/examples/kubernetes/istio/pomerium-helm-values.yml

#### Grafana ini

On the Grafana side we are using the Grafana Helm chart and what follows is the relevant section of the `values.yml` file. The most important thing here is that we need to tell Grafana from which request header to grab the username. In this case that's `X-Pomerium-Claim-Email` because we will be using the user's email (provided by your identity provider) as their username in Grafana. For all the configuration options check out the Grafana documentation about its auth-proxy authentication method.

<<< @/docs/configuration/examples/kubernetes/istio/grafana.ini.yml
