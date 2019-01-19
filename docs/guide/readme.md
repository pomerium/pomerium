# Quick start


## Using Docker

* Install [docker] and [docker-compose].
* Grab Pomerium's included example [`docker-compose.yml`](https://raw.githubusercontent.com/pomerium/pomerium/master/docker-compose.yml) directly or by cloning the repository.
* Update `docker-compose.yml` to match your [identity provider] settings. 
* Copy your subdomain's wild-card TLS certificate next to the compose file. If you don't have one handy, the included [script] generates one from [LetsEncrypt].
* Run docker-compose by runnig the command `$ docker-compose up`. 
* Pomerium is configured to delegate access to two test apps [helloworld] and [httpbin]. Navigate to `hello.corp.example.com` or `httpbin.corp.example.com`. You should see something like the following in your browser and in your terminal. 

![Getting started](./get-started.gif)

[![asciicast](https://asciinema.org/a/tfbSWkUZgMRxHAQDqmcjjNwUg.svg)](https://asciinema.org/a/tfbSWkUZgMRxHAQDqmcjjNwUg)

[docker-compose]: (https://docs.docker.com/compose/install/)
[docker]: https://docs.docker.com/install/
[download]: https://github.com/pomerium/pomerium/releases
[kms]: https://en.wikipedia.org/wiki/Key_management
[certbot]: https://certbot.eff.org/docs/install.html
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
[source]: https://github.com/pomerium/pomerium#start-developing
[identity provider]: ./identity-providers.md
[helloworld]: https://hub.docker.com/r/tutum/hello-world
[httpbin]: https://httpbin.org/
[LetsEncrypt]: https://letsencrypt.org/