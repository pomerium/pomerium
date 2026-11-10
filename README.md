<a href="https://pomerium.com" title="Pomerium is a zero trust, context and identity aware access proxy."><img src="./.github/logo.png" height="138" alt="pomerium logo"></a>

[![Go Report Card](https://goreportcard.com/badge/github.com/pomerium/pomerium)](https://goreportcard.com/report/github.com/pomerium/pomerium)
[![GoDoc](https://pkg.go.dev/badge/github.com/pomerium/pomerium.svg)][godocs]
[![LICENSE](https://img.shields.io/github/license/pomerium/pomerium.svg)](https://github.com/pomerium/pomerium/blob/main/LICENSE)
![Docker Pulls](https://img.shields.io/docker/pulls/pomerium/pomerium)

Pomerium is an identity and context-aware reverse proxy. Pomerium builds secure, clientless connections to internal web apps and other services without a corporate VPN.

Pomerium is:

- **Easier** with [clientless access](https://www.pomerium.com/clientless-access).
- **Faster** by being [tunnel-free and deployed where your apps and services are](https://www.pomerium.com/vpn-replacement).
- **Safer** because [every single action is verified](https://www.pomerium.com/continuous-verification-auditing) before allowed to execute.
- **Tailored** to your organization’s needs by integrating all data for [context-aware access](https://www.pomerium.com/context-aware-access).

It’s not a VPN alternative – it’s the trusted, foolproof way to protect your business. Want a hosted control plane and management GUI? [Give Pomerium Zero a try today](https://console.pomerium.app/create-account?utm_source=github&utm_medium=readme&utm_campaign=github)!

## Docs

For comprehensive docs, and tutorials see our [documentation].

## Contributing

See [Contributing] for information on how you can contribute to Pomerium.

## License

This repository's source code is available under the [Apache License 2.0](./LICENSE). Users compiling from source must comply with the terms of this license.

Official builds that Pomerium publishes, such as the binaries and packages on the [releases](https://github.com/pomerium/pomerium/releases) page, deb and rpm packages, and container images, are available under a [modified Apache 2.0 license](./licenses/POMERIUM-COMMUNITY-LICENSE-1.0.txt).

[contributing]: https://github.com/pomerium/pomerium/blob/main/.github/CONTRIBUTING.md
[documentation]: https://www.pomerium.com/docs/
[godocs]: https://pkg.go.dev/github.com/pomerium/pomerium
