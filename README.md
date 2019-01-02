<img  height="200" src="./docs/logo.png" alt="logo" align="right" >

# Pomerium : identity-aware access proxy
[![Travis CI](https://travis-ci.org/pomerium/pomerium.svg?branch=master)](https://travis-ci.org/pomerium/pomerium)
[![Go Report Card](https://goreportcard.com/badge/github.com/pomerium/pomerium)](https://goreportcard.com/report/github.com/pomerium/pomerium)
[![LICENSE](https://img.shields.io/github/license/pomerium/pomerium.svg?style=flat-square)](https://github.com/pomerium/pomerium/blob/master/LICENSE)

Pomerium is a tool for managing secure access to internal applications and resources. 

Use Pomerium to:

- provide a unified ingress gateway to internal corporate applications. 
- enforce dynamic access policies based on context, identity, and device state. 
- aggregate logging and telemetry data.

To learn more about zero-trust / BeyondCorp, check out [awesome-zero-trust]. 

## Getting started

For instructions on getting started with Pomerium, see our getting started docs.

## To start developing Pomerium

Assuming you have a working [Go environment].

```sh
$ go get -d github.com/pomerium/pomerium
$ cd $GOPATH/src/github.com/pomerium/pomerium
$ make
$ source ./env # see env.example
$ ./bin/pomerium -debug
```

[awesome-zero-trust]: https://github.com/pomerium/awesome-zero-trust
[Go environment]: https://golang.org/doc/install
