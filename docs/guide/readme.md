# Quick start


## Using Docker

* Install [docker](https://docs.docker.com/install/).
* Install [docker-compose](https://docs.docker.com/compose/install/).
* Save Pomerium's example [`docker-compose.yml`]().
* Inspect the `docker-compose.yml` file. In addition to specifying Pomerium's configuration settings, and services, you'll see that there are other included services to give you a feel for how pomerium works. 
* Update the compose file with your [identity provider] settings. 
* Copy your subdomain's wild-card TLS certificate next to the compose file. See included [script] to generate one from LetsEncrypt.
* Run docker compose by runnig the command `$ docker-compose up`. 
* If you navigate to `https://hello.corp.beyondperimeter.com` or `https://httpbin.corp.beyondperimeter.com` where "corp.beyondperimeter.com" is your subdomain in your browser, you should see something like the following in your browser and in your terminal. 

![Getting started](./get-started.gif)

[![asciicast](https://asciinema.org/a/tfbSWkUZgMRxHAQDqmcjjNwUg.svg)](https://asciinema.org/a/tfbSWkUZgMRxHAQDqmcjjNwUg)

[download]: https://github.com/pomerium/pomerium/releases
[kms]: https://en.wikipedia.org/wiki/Key_management
[certbot]: https://certbot.eff.org/docs/install.html
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
[source]: https://github.com/pomerium/pomerium#start-developing
[identity provider]: ./identity-providers.md