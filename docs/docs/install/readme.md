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
  - If you don't have a certificate solution and are testing without a fully qualified domain name (**[FQDN]**), you can use the steps below to set up locally trusted certificates with [mkcert].

### Locally Trusted Certificates

!!!include(install-mkcert.md)!!!

The example configuration in this doc uses `*.localhost.pomerium.io` as the domain path for the demo installation. Create a key pair for this domain:

```bash
mkcert "*.localhost.pomerium.io"
```

This command creates `_wildcard.localhost.pomerium.io.pem` and `_wildcard.localhost.pomerium.io-key.pem`, which we will use later in the process.

## Configure

1. Create a [configuration file] (e.g `config.yaml`) for defining Pomerium's configuration settings, routes, and access policies. Consider the following example:

   <<< @/examples/config/config.docker.yaml

   Keep track of the path to this file, relative to the `docker-compose.yml` file created in the next step. `docker-compose.yml` will need the correct relative path to your `config.yaml`.

1. Create or copy the following `docker-compose.yml` file and modify it to match your configuration, including the correct paths to your `config.yaml` and certificate files:

   <<< @/examples/docker/basic.docker-compose.yml

## Run

Run docker compose:

```bash
docker-compose up
```

Docker will automatically download the required [container images] for Pomerium and [verify]. Then, Pomerium will run with the configuration details set in the previous steps.

You should now be able access to the routes (e.g. `https://verify.localhost.pomerium.io`) as specified in your policy file.

You can also navigate to the special pomerium endpoint `verify.localhost.pomerium.io/.pomerium/` to see your current user details.

![currently logged in user](./img/logged-in-as.png)

## Next Steps

Now you can experiment with adding services to Docker and defining routes and policies for them in Pomerium. See [Guides](/guides/readme.md) for help or inspiration.

::: warning This is a test environment!
Remember, if you followed all the steps in this doc your Pomerium environment is not using trusted certificates. Remember to use a valid certificate solution before moving this configuration to a production environment. See [Certificates][tls certificates] for more information.
:::

[configuration file]: ../../reference/readme.md
[container images]: https://hub.docker.com/r/pomerium/pomerium
[docker]: https://docs.docker.com/install/
[docker-compose]: https://docs.docker.com/compose/install/
[verify]: https://verify.pomerium.com/
[identity provider]: ../identity-providers/readme.md
[tls certificates]: ../topics/certificates.md
[fqdn]: https://en.wikipedia.org/wiki/Fully_qualified_domain_name
[mkcert]: https://github.com/FiloSottile/mkcert