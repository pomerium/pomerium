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

### GKE

- Uses Google Kubernetes Engine's built-in ingress to do [HTTPS load balancing]

<<< @/docs/configuration/examples/helm/helm_gke.sh

### AWS ECS

- Uses Amazon Elastic Container Service

<<< @/docs/configuration/examples/helm/helm_aws.sh

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

#### ingress.yml

<<< @/docs/configuration/examples/kubernetes/ingress.yml

[helloworld]: https://hub.docker.com/r/tutum/hello-world
[httpbin]: https://httpbin.org/
[https load balancing]: https://cloud.google.com/kubernetes-engine/docs/concepts/ingress
