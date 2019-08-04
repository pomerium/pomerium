# Releases

## Binaries

Official binaries for OSX, Windows, and Linux can be found on our [Github Releases](https://github.com/pomerium/pomerium/releases) page.

## Docker

Pomerium is also distributed as a [lightweight](https://github.com/GoogleContainerTools/distroless) [docker container](https://www.docker.com/resources/what-container). You can find Pomerium's images on [dockerhub](https://hub.docker.com/r/pomerium/pomerium) for both AMD64 and a few other architectures. In addition to tagged releases, you can run `latest` which is kept in sync with [master](https://github.com/pomerium/pomerium/tree/master).

```bash
$ docker run pomerium/pomerium:v0.1.0 --version
v0.1.0+53bfa4e
```

## Source

If you'd like to run Pomerium on an [operating system or architecture](https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63) not officially released by Pomerium, or simply prefer to compile from source, you can do so by checking out the latest code and compiling as follows.

```bash
git clone git@github.com:pomerium/pomerium.git
cd pomerium
make
./bin/pomerium --version
```

## Release Cycle

The current release cycle is aligned on a monthly basis. Pre-`1.0.0` we target a `MINOR` release on or around the **last day of each month**. We try to hit the targets as closely as possible, while still delivering a quality release.

## Versioning

Pomerium uses [Semantic Versioning](https://semver.org/). In practice this means for a given version number **vMAJOR**.**MINOR**.**PATCH** (e.g. `v0.1.0`):

- **MAJOR** indicates a incompatible API changes,
- **MINOR** indicates a new functionality in a backwards-compatible manner, and
- **PATCH** indicates a backwards-compatible bug fixe.

As Pomerium is still pre-`v1.0.0`, breaking changes between releases should be expected.

To see difference between releases, please refer to the changelog and upgrading documents.
