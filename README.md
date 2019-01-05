<img  height="175" src="./docs/.vuepress/public/logo.svg" alt="logo" align="right" >

# Pomerium

[![Travis CI](https://travis-ci.org/pomerium/pomerium.svg?branch=master)](https://travis-ci.org/pomerium/pomerium)
[![Go Report Card](https://goreportcard.com/badge/github.com/pomerium/pomerium)](https://goreportcard.com/report/github.com/pomerium/pomerium)
[![LICENSE](https://img.shields.io/github/license/pomerium/pomerium.svg)](https://github.com/pomerium/pomerium/blob/master/LICENSE)

Pomerium is a tool for managing secure access to internal applications and resources.

Use Pomerium to:

- provide a unified gateway to internal corporate applications.
- enforce dynamic access policies based on context, identity, and device state.
- deploy mutually TLS (mTLS) encryption.
- aggregate logging and telemetry data.

To learn more about zero-trust / BeyondCorp, check out [awesome-zero-trust].

## Get started

For instructions on getting started with Pomerium, see our getting started docs.

<img src="./docs/.vuepress/public/getting-started.gif" alt="screen example" align="middle" >

## Start developing

Assuming you have a working [Go environment].

```sh
$ go get -d github.com/pomerium/pomerium
$ cd $GOPATH/src/github.com/pomerium/pomerium
$ make
$ source ./env # see env.example
$ ./bin/pomerium -debug
```

[awesome-zero-trust]: https://github.com/pomerium/awesome-zero-trust
[go environment]: https://golang.org/doc/install
