---
title: Binaries
lang: en-US
meta:
  - name: keywords
    content: pomerium, identity access proxy, oidc, reverse proxy, identity aware proxy
---

# Binaries

This document covers how to configure and run Pomerium using the official prebuilt binaries.

## Prerequisites

- A configured [identity provider]
- [TLS certificates]

## Download

You can download the latest release from GitHub, or use the repositories we provide through [Cloudsmith]. In addition to the easy updates provided by the package manager, the `deb` and `rpm` packages include systemd service unit configurations.

### Operating System Packages

Through [Cloudsmith][cloudsmith-repo], we provide OS packages for Linux distributions using `deb` and `rpm` style package managers. Select your system's package format and architecture, then use the **Setup** tab to add the repository to your package manager.

### Standalone Binary

[Download] the latest release of Pomerium for your machine's operating system and architecture.

## Configure

Pomerium supports setting [configuration variables] using both environmental variables and using a configuration file.

### Configuration file

When using our OS packages, we provide a default configuration at `/etc/pomerium/config.yaml`. Otherwise, create the config file (`config.yaml`) in your preferred location.

This file will be used to determine Pomerium's configuration settings, routes, and access-policies. Consider the following example:

<<< @/examples/config/config.minimal.yaml

You can also set some or all of your configuration keys as environment variables, in an `env` file for example. See the [Reference] page to identify the environment variable for each configuration option.

## Run

### OS Package

1. The following command allows the Pomerium systemd service to bind to [privileged port] `443`:

   ```bash
   echo -e "[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE" | sudo SYSTEMD_EDITOR=tee systemctl edit pomerium
   ```

1. Enable and start the service:

   ```bash
   sudo systemctl enable --now pomerium.service
   ```

### Manual Installation

Source the configuration `env` file, if present, and run pomerium specifying the `config.yaml` .

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
[Cloudsmith]: https://cloudsmith.io
[cloudsmith-repo]: https://cloudsmith.io/~pomerium/repos/pomerium/groups/
[Reference]: /reference/readme.md
[privileged port]: https://www.w3.org/Daemon/User/Installation/PrivilegedPorts.html