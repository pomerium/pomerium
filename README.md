<a href="https://pomerium.com" title="Pomerium is a zero trust, context and identity aware access proxy."><img src="https://www.pomerium.com/wp-content/uploads/2021/08/Pomerium-H-white-bg.png" height="70" alt="pomerium logo"></a>

[![Go Report Card](https://goreportcard.com/badge/github.com/pomerium/pomerium)](https://goreportcard.com/report/github.com/pomerium/pomerium)
[![GoDoc](https://godoc.org/github.com/pomerium/pomerium?status.svg)][godocs]
[![LICENSE](https://img.shields.io/github/license/pomerium/pomerium.svg)](https://github.com/pomerium/pomerium/blob/main/LICENSE)
![Docker Pulls](https://img.shields.io/docker/pulls/pomerium/pomerium)

Pomerium builds secure, clientless connections to internal web apps and services without a corporate VPN.

Pomerium is:

- **Easier** because you don’t have to maintain a client or software.
- **Faster** because it’s deployed directly where your apps and services are. No more expensive data backhauling.
- **Safer** because every single action is verified for trusted identity, device, and context.

It’s not a VPN alternative – it’s the trusted, foolproof way to protect your business.

## Docs

For comprehensive docs, and tutorials see our [documentation].

[documentation]: https://pomerium.com/docs/
[go environment]: https://golang.org/doc/install
[godocs]: https://godoc.org/github.com/pomerium/pomerium
[quick start guide]: https://www.pomerium.com/docs/install/quickstart

## Integration Tests

To run the integration tests locally, first build a local development image:

```bash
./scripts/build-dev-docker.bash
```

Next go to the `integration/clusters` folder and pick a cluster, for example `google-single`, then use docker-compose to start the cluster. We use an environment variable to specify the `dev` docker image we built earlier:

```bash
cd integration/clusters/google-single
env POMERIUM_TAG=dev docker-compose up -V
```

Once that's up and running you can run the integration tests from another terminal:

```bash
go test -count=1 -v ./integration/...
```

If you need to make a change to the clusters themselves, there's a `tpl` folder that contains `jsonnet` files. Make a change and then rebuild the clusters by running:

```bash
go run ./integration/cmd/pomerium-integration-tests/ generate-configuration
```
