# From source

## Prerequisites

- Install [git](https://git-scm.com/) version control system
- Install the [go](https://golang.org/doc/install) programming language
- A configured [identity provider].

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

The command will run all the tests, some code linters, then build the binary. If all is good, you should now have a freshly built pomerium binary in the `pomerium/bin` directory.

## Configure

Make a copy of the [env.example] and name it something like `env`.

```bash
cp env.example env
```

Modify your `env` configuration to to match your [identity provider] settings.

```bash
vim env
```

Place your domain's wild-card TLS certificate next to the compose file. If you don't have one handy, the included [script] generates one from [LetsEncrypt].

## Run

Finally, source the the configuration `env` file and run pomerium.

```bash
source ./env
./bin/pomerium
```

Assuming your configuration file ready to go, you can simply use this one-liner.

```bash
make && source ./env && ./bin/pomerium
```

## Navigate

Browse to `httpbin.your.domain.com`. You should see something like the following in your browser.

![Getting started](./get-started.gif)

[certbot]: https://certbot.eff.org/docs/install.html
[docker]: https://docs.docker.com/install/
[docker-compose]: (https://docs.docker.com/compose/install/)
[download]: https://github.com/pomerium/pomerium/releases
[env.example]: https://github.com/pomerium/pomerium/blob/master/env.example
[google gke]: https://cloud.google.com/kubernetes-engine/docs/quickstart#create_cluster
[helloworld]: https://hub.docker.com/r/tutum/hello-world
[httpbin]: https://httpbin.org/
[identity provider]: ../docs/identity-providers.md
[letsencrypt]: https://letsencrypt.org/
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
