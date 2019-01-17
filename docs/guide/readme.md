# Quick start


## Using Docker

1. Install [docker](https://docs.docker.com/install/).
1. Install [docker-compose](https://docs.docker.com/compose/install/).
1. Save Pomerium's example [`docker-compose.yml`]().
1. Inspect the `docker-compose.yml` file. In addition to specifying Pomerium's configuration settings, and services, you'll see that there are other included services to give you a feel for how pomerium works. 
1. Update the compose file with your [identity provider] settings. 
1. Copy your subdomain's wild-card TLS certificate next to the compose file. See included [script] to generate one from LetsEncrypt.
1. Run docker compose by runnig the command `$ docker-compose up`. 
1. You should see something like the following in your terminal and in your browser when you navigate to https://hello.corp.beyondperimeter.com or https://httpbin.corp.beyondperimeter.com where "corp.beyondperimeter.com" is your subdomain.

![Getting started](./get-started.gif)

[![asciicast](https://asciinema.org/a/tfbSWkUZgMRxHAQDqmcjjNwUg.svg)](https://asciinema.org/a/tfbSWkUZgMRxHAQDqmcjjNwUg)

[download]: https://github.com/pomerium/pomerium/releases
[kms]: https://en.wikipedia.org/wiki/Key_management
[certbot]: https://certbot.eff.org/docs/install.html
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
[source]: https://github.com/pomerium/pomerium#start-developing
[identity provider]: ./identity-providers.md