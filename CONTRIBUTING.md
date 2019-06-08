# Contributing to Pomerium

Thanks for your interest in contributing to Pomerium! We welcome all contributions, from new features to documentation updates. This document describes how you can find issues to work on, setup Pomerium locally for development, and get help when you are stuck.

## Picking Tasks

We make use of Github Issues for defining tasks to work on. If you're looking for a specific task to work on, check out [the repository's issues](https://github.com/pomerium/pomerium/issues). We've tagged some issues with the [help-wanted tag](https://github.com/pomerium/pomerium/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22), but feel free to pick up any issue that looks interesting to you or fix a bug you stumble across in the course of using Pomerium.

For larger features, we'd appreciate it if you open a new issue before doing a ton of work to discuss the feature before you start writing a lot of code.

## Hacking on Pomerium

For issues that require code changes, you'll have to setup Pomerium locally from the source code.

### Prerequisites

- [Fork the repository](https://help.github.com/en/articles/fork-a-repo)
- Install [Go 1.12](https://golang.org/doc/install) or later
- (Optional) Node.js and npm for modifying the docs

### Setup Sources Locally

Download the forked sources to your go workspace with `go get`:

```bash
go get github.com/your-github-username/pomerium
```

Notice the sources have a `go.mod` file. Install the dependencies with go modules:

```bash
go mod download
```

### Configure

Configure Pomerium as described in the [latest version of the docs](https://www.pomerium.io/). This includes setting the configuration via `config.yaml` or environment variables.

#### Reverse-Proxy Traffic on Development Host

If you plan on reverse-proxying traffic against the locally running version of Pomerium, the `policy` must be carefully configured. This configuration is highly dependent on whether your local development can accept ingress HTTPS traffic that hits your public IP address via DNS resolution. If you can send public traffic to your local development host (usually via port forwarding on your router), then configure the policy with subdomains for each route. This is described in the [documentation's configuration reference](https://www.pomerium.io/).

Otherwise, the simpliest method to allow traffic is to only define _one route_ for `https://localhost:443`. This way, you'll have Pomerium running such that it can reverse-proxy traffic to a single backend:

```yml
- from: https://localhost
  to: http://localhost:8081
  ...
```

**Note:** Do not include the port number in the routes' `from` value.

If you wish to support reverse-proxying traffic to multiple backends when your local development host does not accept public HTTPS traffic, see the [Known Limitations and Workarounds](#known-limitations-and-workarounds) section.

### Run

Use Go to run `main.go` in the repository's `cmd/` directory, providing the path to the configuration file (if used):

```bash
go run cmd/pomerium/main.go --config config.yaml
```

Congrats! You now have the latest version of Pomerium running locally, ready to proxy your traffic. Try sending it traffic from your web browser or `curl`.

## Known Limitations and Workarounds

This section is a FAQ for pomerium developers.

### Full Reverse-Proxy Support Locally

If you wish to support reverse-proxying traffic to multiple backends when your local development host does not accept public HTTPS traffic, you can still do so with a manual hack. You must configure your operating system's `hosts` file to redirect a random domain to `localhost`, and then use subdomains of that random domain in the policy. See [pomerium/pomerium#146](https://github.com/pomerium/pomerium/issues/146#issuecomment-497131269) for more information.

### Running on Windows 10

Some parts of Pomerium do not work correctly on Windows 10. Specifically, you might run into the following error described in [golang/go#16736](https://github.com/golang/go/issues/16736):

```bash
crypto/x509: system root pool is not available on Windows
```

Two workarounds exist, the first one less _hacky_ than the first:

1. Run pomerium on [Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/faq). This will require you to redo all the setup (like installing Go) on WSL.
2. Edit the external go modules' code in `src/crypto/x509/cert_pool.go` to delete the entire `if` statement described in [golang/go#16736](https://github.com/golang/go/issues/16736). This should allow pomerium to run for simple use-cases, but some of the unit tests might fail. **WARNING:** You probably shouldn't run any sensitive backends behind pomerium when you do this, as this definitely circumvents some security precautions.

## Submitting a Pull Request

We make use of Github Pull Requests for reviewing and accepting your contributions. When you're ready, make sure you've run the tests and updated the docs, then submit a Pull Request.

## Getting Help

Feel free to [join our slack channel](http://slack.pomerium.io/) if you're confused on anything. Once again, thanks for your interest in contributing!
