# Pomerium as auth proxy for TiddlyWiki

Run this demo locally on your docker-compose capable workstation, or replace `localhost.pomerium.io` with your own domain if running on a server.

## Includes

- Authentication and Authorization managed by pomerium

## How

- Update `config.yaml` for your e-mail address, if not using gmail/google.
- Replace secrets in `config.yaml`.
- Replace `email.is` in `config.yaml`
- Configure read-only or writer users by changing readers and writers parameter of tiddlywiki in `docker-compose.yaml`.
- Run `docker-compose up` from this directory.
- Navigate to `https://wiki.localhost.pomerium.io`
