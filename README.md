<a href="https://pomerium.io" title="Pomerium is a zero trust, context and identity aware access proxy."><img src="https://www.pomerium.com/wp-content/uploads/2020/07/logo-long.svg" height="70" alt="pomerium logo"></a>

[![pomerium chat](https://img.shields.io/badge/chat-on%20slack-blue.svg?style=flat&logo=slack)](http://slack.pomerium.io)
[![Travis CI](https://travis-ci.org/pomerium/pomerium.svg?branch=master)](https://travis-ci.org/pomerium/pomerium) [![Go Report Card](https://goreportcard.com/badge/github.com/pomerium/pomerium)](https://goreportcard.com/report/github.com/pomerium/pomerium) [![GoDoc](https://godoc.org/github.com/pomerium/pomerium?status.svg)][godocs] [![LICENSE](https://img.shields.io/github/license/pomerium/pomerium.svg)](https://github.com/pomerium/pomerium/blob/master/LICENSE) [![codecov](https://img.shields.io/codecov/c/github/pomerium/pomerium.svg?style=flat)](https://codecov.io/gh/pomerium/pomerium) ![Docker Pulls](https://img.shields.io/docker/pulls/pomerium/pomerium)

Pomerium is an identity-aware proxy that enables secure access to internal applications. Pomerium provides a standardized interface to add access control to applications regardless of whether the application itself has authorization or authentication baked-in. Pomerium gateways both internal and external requests, and can be used in situations where you'd typically reach for a VPN.

Pomerium can be used to:

- provide a **single-sign-on gateway** to internal applications.
- enforce **dynamic access policy** based on **context**, **identity**, and **device state**.
- aggregate access logs and telemetry data.
- a **VPN alternative**.

## Docs

For comprehensive docs, and tutorials see our [documentation].

[documentation]: https://www.pomerium.io/
[go environment]: https://golang.org/doc/install
[godocs]: https://godoc.org/github.com/pomerium/pomerium
[quick start guide]: https://www.pomerium.io/guide/
