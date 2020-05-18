---
title: From Source
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc reverse-proxy from-source
---

# From Source

The following quick-start guide covers how to retrieve and build Pomerium from its source-code as well as how to run Pomerium using a minimal but complete configuration. One of the benefits of compiling from source is that Go supports building static binaries for a [wide array of architectures and operating systems](https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63).

## Prerequisites

- [git](https://git-scm.com/)
- [go](https://golang.org/doc/install) programming language
- A configured [identity provider]

## Download

Retrieve the latest copy of pomerium's source code by cloning the repository.

```bash
git clone https://github.com/pomerium/pomerium.git $HOME/pomerium
```

## Create local certs

In production, we'd use a public certificate authority such as LetsEncrypt. For local development, we can use [mkcert](https://mkcert.dev/) to make locally trusted development certificates with any names you'd like.

```bash
# Install mkcert.
go get -u github.com/FiloSottile/mkcert
# Bootstrap mkcert's root certificate into your operating system's trust store.
mkcert -install
# Create your wildcard domain.
# *.localhost.pomerium.io is helper domain we've hard-coded to route to localhost
mkcert "*.localhost.pomerium.io"
```

## Build

Build Pomerium from source in a single step using make.

```bash
cd $HOME/pomerium
make
```

[Make] will run all the tests, some code linters, then build the binary. If all is good, you should now have a freshly built Pomerium binary for your architecture and operating system in the `pomerium/bin` directory.

## Configure

Pomerium supports setting [configuration variables] using both environmental variables and using a configuration file.

## Configuration file

Create a config file (`config.yaml`). This file will be use to determine Pomerium's configuration settings, routes, and access-policies. Consider the following example:

<<< @/docs/configuration/examples/config/config.minimal.yaml

## Run

Finally, run Pomerium specifying the configuration file `config.yaml`.

```bash
make && ./bin/pomerium -config config.yaml
```

### Navigate

Browse to `httpbin.localhost.pomerium.io`. Connections between you and [httpbin] will now be proxied and managed by Pomerium.

[configuration variables]: ../../configuration/readme.md
[httpbin]: https://httpbin.org/
[identity provider]: ../identity-providers/
[make]: https://en.wikipedia.org/wiki/Make_(software)
[tls certificates]: ../reference/certificates.md
