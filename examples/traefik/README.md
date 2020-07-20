# Pomerium as forward-auth provider for Traefik

Run this demo locally on your docker-compose capable workstation, or replace `localhost.pomerium.io` with your own domain if running on a server.

## Includes

- Authentication and Authorization managed by pomerium
- Routing / reverse proxying handled by traefik

## How

- Update `config.yaml` for your e-mail address, if not using gmail/google.
- Replace secrets in `config.yaml`.
- Run `docker-compose up` from this directory.
- Navigate to `https://httpbin.localhost.pomerium.io`
- ???
- Profit
