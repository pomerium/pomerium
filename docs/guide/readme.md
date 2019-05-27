# Docker

Docker and docker-compose are tools for defining and running multi-container Docker applications. We've created an example docker-compose file that creates a minimal, but complete test environment for pomerium.

## Prerequisites

- A configured [identity provider]
- Install [docker]
- Install [docker-compose]
- A [wild-card TLS certificate](../docs/certificates.md)

## Download

Copy and paste the contents of the provided example [basic.docker-compose.yml].

## Configure

### Docker-compose

Edit the `docker-compose.yml` to match your specific [identity provider]'s settings. For example, `basic.docker-compose.yml`:

<<< @/docs/docs/examples/docker/basic.docker-compose.yml

### Policy configuration

Next, create a configuration file which will contain the routes you want to proxy, and their desired access-controls. For example, `config.example.policy.only.yaml`:

<<< @/config.example.policy.only.yaml

### Certificates

Place your domain's wild-card TLS certificate next to the compose file. If you don't have one handy, the included [script] generates one from [LetsEncrypt].

## Run

Docker-compose will automatically download the latest pomerium release as well as two example containers.

```bash
docker-compose up
```

Pomerium is configured to delegate access to two test apps [helloworld] and [httpbin].

## Navigate

Open a browser and navigate to `hello.your.domain.com` or `httpbin.your.domain.com`. You should see something like the following in your browser.

![Getting started](./get-started.gif)

And in your terminal.

[![asciicast](https://asciinema.org/a/tfbSWkUZgMRxHAQDqmcjjNwUg.svg)](https://asciinema.org/a/tfbSWkUZgMRxHAQDqmcjjNwUg)

[basic.docker-compose.yml]: ../docs/examples.html#basic-docker-compose-yml
[docker]: https://docs.docker.com/install/
[docker-compose]: https://docs.docker.com/compose/install/
[helloworld]: https://hub.docker.com/r/tutum/hello-world
[httpbin]: https://httpbin.org/
[identity provider]: ../docs/identity-providers.md
[letsencrypt]: https://letsencrypt.org/
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
