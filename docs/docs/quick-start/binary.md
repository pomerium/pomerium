---
title: Binaries
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc reverse-proxy
---

# Binaries

The following quick-start guide covers how to configure and run Pomerium using the official prebuilt binaries.

## Prerequisites

- A configured [identity provider]
- [TLS certificates]

## Download

[Download] the latest release of Pomerium for your machine's operating system and architecture.

## Configure

Pomerium supports setting [configuration variables] using both environmental variables and using a configuration file.

### Configuration file

Create a config file (`config.yaml`). This file will be used to determine Pomerium's configuration settings, routes, and access-policies. Consider the following example:

<<< @/examples/config/config.minimal.yaml

### Environmental Variables

As mentioned above, Pomerium supports mixing and matching configuration. For example, we can specify our secret values and domains certificates as [environmental configuration variables], and set the rest as part of the configuration file.

<<< @/examples/config/config.minimal.env

## Run

Finally, source the configuration `env` file and run pomerium specifying the `config.yaml` .

```bash
source ./env
./bin/pomerium -config config.yaml
```

## Navigate

Browse to `external-httpbin.your.domain.example`. Connections between you and [httpbin] will now be proxied and managed by Pomerium.

[configuration variables]: ../../configuration/readme.md
[download]: https://github.com/pomerium/pomerium/releases
[environmental configuration variables]: https://12factor.net/config
[httpbin]: https://httpbin.org/
[identity provider]: ../identity-providers/
[make]: https://en.wikipedia.org/wiki/Make_(software)
[tls certificates]: ../reference/certificates.md
