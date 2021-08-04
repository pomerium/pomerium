---
title: Download
sidebarDepth: 2
description: This article describes various ways to install pomerium
---

# Releases

Pomerium is shipped in multiple formats and architectures to suit a variety of deployment patterns. There are two binaries:

- `pomerium` is the primary server component. It is a monolithic binary that can perform the function of any [services mode](/reference/readme.md#service-mode).
- `pomerium-cli` (optional) is a command-line client for working with Pomerium.  Functions include acting as an authentication helper for tools like [kubtctl](topics/kubernetes-integration.md).


[[toc]]


## pomerium

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

### Packages

- Supported formats: `rpm`, `deb`
- Requires `systemd` support

Official packages can be found on our [GitHub Releases](https://github.com/pomerium/pomerium/releases) page or from [Cloudsmith](https://cloudsmith.io/~pomerium/repos/pomerium/packages/).

- [RPM Instructions](https://cloudsmith.io/~pomerium/repos/pomerium/setup/#formats-rpm)
- [Deb Instructions](https://cloudsmith.io/~pomerium/repos/pomerium/setup/#formats-deb)

#### Example yum repo

```
[pomerium-pomerium]
name=pomerium-pomerium
baseurl=https://dl.cloudsmith.io/public/pomerium/pomerium/rpm/el/$releasever/$basearch
repo_gpgcheck=1
enabled=1
gpgkey=https://dl.cloudsmith.io/public/pomerium/pomerium/gpg.6E388440B94E1407.key
gpgcheck=1
sslverify=1
pkg_gpgcheck=1
```
#### Example deb setup

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/pomerium/pomerium/gpg.6E388440B94E1407.key' | apt-key add -
echo "deb https://dl.cloudsmith.io/public/pomerium/pomerium/deb/debian buster main" > /etc/apt/sources.list.d/pomerium-pomerium.list
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

  ```bash
  docker pull pomerium/pomerium:latest
  ```

### Helm

Pomerium maintains a [helm](https://helm.sh) chart for easy Kubernetes deployment with best practices <https://helm.pomerium.io/>

```bash
helm repo add pomerium https://helm.pomerium.io
helm install pomerium/pomerium
```

See the [README](https://github.com/pomerium/pomerium-helm/blob/master/charts/pomerium/README.md) for up to date install options.

### Source

::: tip

Officially supported build platforms are limited by [envoy proxy](https://www.envoyproxy.io/). If you have an enoy binary for your platform in your path at start time, `pomerium` should function correctly.

:::

```bash
git clone git@github.com:pomerium/pomerium.git
cd pomerium
make
./bin/pomerium --version
```

## pomerium-cli

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

### Packages

- Supported formats: `rpm`, `deb`

Official packages can be found on our [GitHub Releases](https://github.com/pomerium/pomerium/releases) page or from [Cloudsmith](https://cloudsmith.io/~pomerium/repos/pomerium/packages/).

- [RPM Instructions](https://cloudsmith.io/~pomerium/repos/pomerium/setup/#formats-rpm)
- [Deb Instructions](https://cloudsmith.io/~pomerium/repos/pomerium/setup/#formats-deb)

#### Example yum repo

```
[pomerium-pomerium]
name=pomerium-pomerium
baseurl=https://dl.cloudsmith.io/public/pomerium/pomerium/rpm/el/$releasever/$basearch
repo_gpgcheck=1
enabled=1
gpgkey=https://dl.cloudsmith.io/public/pomerium/pomerium/gpg.6E388440B94E1407.key
gpgcheck=1
sslverify=1
pkg_gpgcheck=1
```
#### Example deb setup

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/pomerium/pomerium/gpg.6E388440B94E1407.key' | apt-key add -
echo "deb https://dl.cloudsmith.io/public/pomerium/pomerium/deb/debian buster main" > /etc/apt/sources.list.d/pomerium-pomerium.list
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
make build NAME=pomerium-cli
./bin/pomerium-cli --help
```

## Release cycle

The current release cycle is aligned on a monthly basis. Pre-`1.0.0` we target a `MINOR` release on or around the **first day of each month**. We try to hit the targets as closely as possible, while still delivering a quality release.

Pomerium uses [Semantic Versioning](https://semver.org/). In practice this means for a given version number **vMAJOR**.**MINOR**.**PATCH** (e.g. `v0.1.0`):

- **MAJOR** indicates an incompatible API change,
- **MINOR** indicates a new functionality in a backwards-compatible manner, and
- **PATCH** indicates a backwards-compatible bug fixe.

As Pomerium is still pre-`v1.0.0`, breaking changes between releases should be expected.

To see difference between releases, please refer to the changelog and upgrading documents.
