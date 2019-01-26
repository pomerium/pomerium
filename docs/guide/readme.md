# Quick start

## Using Docker

- Install [docker] and [docker-compose].
- Grab Pomerium's included example [`docker-compose.yml`](https://raw.githubusercontent.com/pomerium/pomerium/master/docker-compose.yml) directly or by cloning the repository.
- Update `docker-compose.yml` to match your [identity provider] settings.
- Copy your subdomain's wild-card TLS certificate next to the compose file. If you don't have one handy, the included [script] generates one from [LetsEncrypt].
- Run docker-compose by runnig the command `$ docker-compose up`.
- Pomerium is configured to delegate access to two test apps [helloworld] and [httpbin]. Navigate to `hello.corp.example.com` or `httpbin.corp.example.com`. You should see something like the following in your browser and in your terminal.

![Getting started](./get-started.gif)

[![asciicast](https://asciinema.org/a/tfbSWkUZgMRxHAQDqmcjjNwUg.svg)](https://asciinema.org/a/tfbSWkUZgMRxHAQDqmcjjNwUg)

## From source

### Get the code

Using [git](https://git-scm.com/), retrieve the latest copy of pomerium's source code by cloning the repository.

```bash
# where `$HOME/pomerium` is the directory you want to save pomerium
git clone https://github.com/pomerium/pomerium.git $HOME/pomerium
```

Build pomerium from source in a single step using make.

```bash
cd $HOME/pomerium
make
```

The command will run all the tests, some code linters, then build the binary. If all is good, you should now have a freshly built pomerium binary in the `pomerium/bin` directory.

### Configure

Make a copy of the [env.example] and name it something like `env`.

```bash
cp env.example env
```

Modify your `env` configuration to to match your [identity provider] settings.

```bash
vim env
```

### Run

Finally, source the the configuration `env` file and run pomerium.

```bash
source ./env
./bin/pomerium
```

### All-in-one

Assuming your configuration file ready to go, you can simply use this one-liner.

```bash
make && source ./env && ./bin/pomerium
```

[certbot]: https://certbot.eff.org/docs/install.html
[docker]: https://docs.docker.com/install/
[docker-compose]: (https://docs.docker.com/compose/install/)
[download]: https://github.com/pomerium/pomerium/releases
[env.example]: https://github.com/pomerium/pomerium/blob/master/env.example
[helloworld]: https://hub.docker.com/r/tutum/hello-world
[httpbin]: https://httpbin.org/
[identity provider]: ./identity-providers.md
[kms]: https://en.wikipedia.org/wiki/Key_management
[letsencrypt]: https://letsencrypt.org/
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
[source]: https://github.com/pomerium/pomerium#start-developing
