---
title: Docker
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc docker reverse-proxy containers
---

# Pomerium using Docker

In the following quick-start, we'll create a minimal but complete environment for running Pomerium with containers.

## Prerequisites

- A configured [identity provider]
- [Docker] and [docker-compose]
- A [wild-card TLS certificate]

## Configure

### Configuration file

Create a [configuration file] (e.g `config.yaml`) for defining Pomerium's configuration settings, routes, and access-policies. Consider the following example:

<<< @/docs/configuration/examples/config/config.minimal.yaml

Ensure the `docker-compose.yml` contains the correct path to your `config.yaml`.

### Docker-compose

Download the following `docker-compose.yml` file and modify it to:

- generate new secrets
- mount your [wild-card TLS certificate]
- mount your `config.yaml` [configuration file]

<<< @/docs/configuration/examples/docker/basic.docker-compose.yml

## Run

Finally, simply run docker compose.

```bash
docker-compose up
```

Docker will automatically download the required [container images] for Pomerium and [httpbin]. Then, Pomerium will run with the configuration details set in the previous steps.

You should now be able access to the routes (e.g. `https://httpbin.corp.yourdomain.example`) as specified in your policy file.

You can also navigate to the special pomerium endpoint `httpbin.corp.yourdomain.example/.pomerium/` to see your current user details.

![currently logged in user](./img/logged-in-as.png)

[configuration file]: ../../configuration/readme.md
[container images]: https://hub.docker.com/r/pomerium/pomerium
[docker]: https://docs.docker.com/install/
[docker-compose]: https://docs.docker.com/compose/install/
[httpbin]: https://httpbin.org/
[identity provider]: ../identity-providers/readme.md
[wild-card tls certificate]: ../reference/certificates.md
