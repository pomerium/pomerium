---
title: Binaries
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc reverse-proxy
---

# Binaries

This document covers how to configure and run Pomerium using the official prebuilt binaries.

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

## Run

Finally, source the configuration `env` file and run pomerium specifying the `config.yaml` .

```bash
./bin/pomerium -config config.yaml
```

## Navigate

Browse to `external-verify.your.domain.example`. Connections between you and [verify] will now be proxied and managed by Pomerium.

[configuration variables]: /reference/readme.md
[download]: https://github.com/pomerium/pomerium/releases
[verify]: https://verify.pomerium.com/
[identity provider]: /docs/identity-providers/readme.md
[tls certificates]: /docs/topics/certificates.md
