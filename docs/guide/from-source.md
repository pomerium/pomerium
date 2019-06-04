---
title: From Source
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc git reverse-proxy
---

# Building Pomerium From Source

The following quick-start guide covers how to retrieve and build Pomerium directly from it's source-code as well as how to run Pomerium using a minimal but complete configuration. One of the benefits of compiling from source is that Go supports building static binaries for a [wide array of architectures and operating systems](https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63) — some of which may not yet be supported by Pomerium's official images or binaries. 

## Prerequisites

-  [git](https://git-scm.com/) 
-  [go](https://golang.org/doc/install) programming language
- A configured [identity provider]
- A [wild-card TLS certificate]

## Download

Retrieve the latest copy of pomerium's source code by cloning the repository.

```bash
git clone https://github.com/pomerium/pomerium.git $HOME/pomerium
```

## Make

Build pomerium from source in a single step using make.

```bash
cd $HOME/pomerium
make
```

[Make] will run all the tests, some code linters, then build the binary. If all is good, you should now have a freshly built pomerium binary for your architecture and operating system in the `pomerium/bin` directory.

## Configure

Pomerium supports setting [configuration variables] using both environmental variables and using a configuration file.

### Configuration file

Create a config file (`config.yaml`). This file will be use to determine Pomerium's configuration settings, routes, and access-policies. Consider the following example:

<<< @/docs/docs/examples/config/config.minimal.yaml

### Environmental Variables

As mentioned above, Pomerium supports mixing and matching where configuration details are set. For example, we can specify our secret values and domains certificates as [environmental configuration variables].

<<< @/docs/docs/examples/config/config.minimal.env

## Run

Finally, source the the configuration `env` file and run pomerium specifying the configuration file `config.yaml`.

```bash
source ./env
./bin/pomerium -config config.yaml
```

## Navigate

Browse to `external-httpbin.your.domain.example`. Connections between you and [httpbin] will now be proxied and managed by Pomerium. 

[configuration variables]: ../reference/readme.md
[download]: https://github.com/pomerium/pomerium/releases
[environmental configuration variables]: https://12factor.net/config
[httpbin]: https://httpbin.org/
[identity provider]: ../docs/identity-providers.md
[make]: https://en.wikipedia.org/wiki/Make_(software)
[wild-card tls certificate]: ../docs/certificates.md
