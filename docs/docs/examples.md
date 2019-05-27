---
sidebarDepth: 3
---

# Example configs

A collection of copy-and-paste-able configurations for various types of clouds, use-cases, and deployments. These files can also be found in the git repository in the `docs/docs/examples/` directory.

:::tip

Remember to set your identity provider settings and to generate new secret keys!

:::

## Binary

- Suitable for bare-metal and virtual-machines
- No docker, docker-compose, or kubernetes required
- Minimal configuration
- Pomerium services are run in "all-in-one" mode
- No load balancer required
- Great for testing Pomerium
- Routes default to hosted version of httpbin.org

Customize for your identity provider and run `./bin/pomerium -config config.yaml`

<<< @/config.example.yaml

## Docker

Uses the [latest pomerium build](https://hub.docker.com/r/pomerium/pomerium) from docker hub. Docker and docker-compose are great tools for standing up and testing multiple service, and containers without having to stand-up a full on cluster.

#### Basic

- Minimal container-based configuration.
- Docker and Docker-Compose based.
- Runs a single container for all pomerium services
- Routes default to on-premise [helloworld], [httpbin].

Customize for your identity provider run `docker-compose up -f basic.docker-compose.yml`

#### basic.docker-compose.yml

<<< @/docs/docs/examples/docker/basic.docker-compose.yml

#### NGINX micro-services

- Docker and Docker-Compose based.
- Uses pre-configured built-in nginx load balancer
- Runs separate containers for each service
- Routes default to on-premise [helloworld], and [httpbin].

Customize for your identity provider run `docker-compose up -f nginx.docker-compose.yml`

#### nginx.docker-compose.yml

<<< @/docs/docs/examples/docker/nginx.docker-compose.yml

## Helm

- HTTPS (TLS) between client, load balancer, and services
- gRPC requests are routed behind the load balancer
- Routes default to hosted version of httpbin.org
- Includes installer script

#### helm_gke.sh

- Uses Google Kubernetes Engine's built-in ingress to do [HTTPS load balancing]

<<< @/scripts/helm_gke.sh

#### helm_aws.sh

- Uses Amazon Elastic Container Service

<<< @/scripts/helm_aws.sh

## Kubernetes

- Uses Google Kubernetes Engine's built-in ingress to do [HTTPS load balancing]
- HTTPS (TLS) between client, load balancer, and services
- gRPC requests are routed behind the load balancer
- Routes default to hosted version of httpbin.org
- Includes installer script

#### kubernetes_gke

<<< @/scripts/kubernetes_gke.sh

#### authenticate.deploy.yml

<<< @/docs/docs/examples/kubernetes/authenticate.deploy.yml

#### authenticate.service.yml

<<< @/docs/docs/examples/kubernetes/authenticate.service.yml

#### authorize.deploy.yml

<<< @/docs/docs/examples/kubernetes/authorize.deploy.yml

#### authorize.service.yml

<<< @/docs/docs/examples/kubernetes/authorize.service.yml

#### proxy.deploy.yml

<<< @/docs/docs/examples/kubernetes/proxy.deploy.yml

#### proxy.service.yml

<<< @/docs/docs/examples/kubernetes/proxy.service.yml

#### ingress.yml

<<< @/docs/docs/examples/kubernetes/ingress.yml

[helloworld]: https://hub.docker.com/r/tutum/hello-world
[httpbin]: https://httpbin.org/
[https load balancing]: https://cloud.google.com/kubernetes-engine/docs/concepts/ingress
