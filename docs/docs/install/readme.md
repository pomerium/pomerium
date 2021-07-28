---
title: Quick-Start
lang: en-US
description: Get Pomerium up and running quickly with Docker.
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc docker reverse-proxy containers
---

# Pomerium using Docker

In this quick-start document, we'll create a minimal but complete environment for running Pomerium with containers.

## Prerequisites

- A configured [identity provider]
- [Docker] and [docker-compose]
- [TLS certificates]

## Configure

### Configuration file

Create a [configuration file] (e.g `config.yaml`) for defining Pomerium's configuration settings, routes, and access-policies. Consider the following example:

<<< @/examples/config/config.minimal.yaml

Ensure the `docker-compose.yml` contains the correct path to your `config.yaml`.

### Autocert Docker-compose
Ensure you have set up the requisite DNS and port forwarding in [TLS certificates]

Download the following `docker-compose.yml` file and modify it to:

- generate new secrets
- mount your [TLS certificates]
- mount your `config.yaml` [configuration file]
- Set `autocert_use_staging` to `false` once you have finished testing

<<< @/examples/docker/autocert.docker-compose.yml

Please note that you should use a persistent volume to store certificate data, or you may exhaust your domain quota on Let's Encrypt.

### Wildcard Docker-compose

Download the following `docker-compose.yml` file and modify it to:

- generate new secrets
- mount your [TLS certificates]
- mount your `config.yaml` [configuration file]

<<< @/examples/docker/basic.docker-compose.yml

## Run

Finally, simply run docker compose.

```bash
docker-compose up
```

Docker will automatically download the required [container images] for Pomerium and [verify]. Then, Pomerium will run with the configuration details set in the previous steps.

You should now be able access to the routes (e.g. `https://verify.localhost.pomerium.io`) as specified in your policy file.

You can also navigate to the special pomerium endpoint `verify.corp.yourdomain.example/.pomerium/` to see your current user details.

![currently logged in user](./img/logged-in-as.png)

[configuration file]: ../../reference/readme.md
[container images]: https://hub.docker.com/r/pomerium/pomerium
[docker]: https://docs.docker.com/install/
[docker-compose]: https://docs.docker.com/compose/install/
[verify]: https://verify.pomerium.com/
[identity provider]: ../identity-providers/readme.md
[tls certificates]: ../topics/certificates.md
