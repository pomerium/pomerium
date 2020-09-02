---
title: Installation
sidebarDepth: 2
description: >-
  This article describes various ways to install pomerium
---

# Installation

## Overview

Pomerium is shipped in multiple formats and architectures to suit a variety of deployment patterns.  There are two binaries:

`pomerium` is the server component.  It is a monolithic binary that can perform the function of any [services mode](/reference/#service-mode), depending on configuration.

`pomerium-cli` is the user component.  It is a similarly monolithic binary handling user facing capabilities such as pomerium service account creation and authentication helper functions.

## Pomerium

- Supported Operating Systems: `linux`, `darwin`
- Supported Architectures: `amd64`, `arm64`

### Binaries

Official binaries can be found on our [GitHub Releases](https://github.com/pomerium/pomerium/releases) page.

```shell
ARCH=[your arch]
OS=[your os]
VERSION=[desired version]
curl -L https://github.com/pomerium/pomerium/releases/download/${VERSION}/pomerium-${OS}-${ARCH}.tar.gz \
    | tar -z -x
```

### Docker Image

Pomerium utilizes a [minimal](https://github.com/GoogleContainerTools/distroless) [docker container](https://www.docker.com/resources/what-container). You can find Pomerium's images on [dockerhub](https://hub.docker.com/r/pomerium/pomerium). Pomerium can be pulled in several flavors and architectures.

- `:vX.Y.Z`: which will pull the a [specific tagged release](https://github.com/pomerium/pomerium/tags).

  ```bash
  $ docker run pomerium/pomerium:v0.1.0 --version
  v0.1.0+53bfa4e
  ```

- `:latest`: which will pull the [most recent tagged release](https://github.com/pomerium/pomerium/releases).

  ```bash
  $ docker pull pomerium/pomerium:latest && docker run pomerium/pomerium:latest --version
  v0.2.0+87e214b
  ```

- `:master` : which will pull an image in sync with git's [master](https://github.com/pomerium/pomerium/tree/master) branch.

```shell
docker pull pomerium/pomerium:latest
```

### Helm

Pomerium maintains a [helm](https://helm.sh) chart for easy Kubernetes deployment with best practices [https://helm.pomerium.io/](https://helm.pomerium.io/)

```shell
helm repo add pomerium https://helm.pomerium.io
helm install pomerium/pomerium
```

See the [README](https://github.com/pomerium/pomerium-helm/blob/master/charts/pomerium/README.md) for up to date install options.

### Source

::: tip
Officially supported build platforms are limited by envoy proxy.  If you have an
enoy binary for your platform in your path at start time, `pomerium` should function correctly.
:::

```shell
git clone git@github.com:pomerium/pomerium.git
cd pomerium
make
./bin/pomerium --version
```

## Pomerium CLI

- Supported Operating Systems: `linux`, `darwin`, `windows`, `freebsd`
- Supported Architectures: `amd64`, `arm64`, `armv6`, `armv7`

### Binaries

Official binaries can be found on our [GitHub Releases](https://github.com/pomerium/pomerium/releases) page.

```shell
ARCH=[your arch]
OS=[your os]
VERSION=[desired version]
curl -L https://github.com/pomerium/pomerium/releases/download/${VERSION}/pomerium-cli-${OS}-${ARCH}.tar.gz \
    | tar -z -x
```

### Homebrew

```shell
brew tap pomerium/tap
brew install pomerium-cli
```

### Source

```shell
git clone git@github.com:pomerium/pomerium.git
cd pomerium
make
./bin/pomerium-cli --help
```
