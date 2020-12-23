# Pomerium as a TCP proxy for SSH and Redis

Run this demo locally on your docker-compose capable workstation, or replace `localhost.pomerium.io` with your own domain if running on a server.

## Includes

- TCP connection authentication and authorization managed by pomerium
- SSH client configuration and demo server
- Redis demo server
- Postgres demo server

## How

- [Install](https://www.pomerium.com/docs/installation.html#pomerium-cli) `pomerium-cli` in your `$PATH`
- Update `config.yaml` for your e-mail address, if not using gmail/google
- Replace secrets in `config.yaml`
- Run `docker-compose up` from this directory
- SSH:
  - Run `ssh -F ssh_config myuser@ssh.localhost.pomerium.io`
  - Log in with password `supersecret`
- Redis:
  - Run `pomerium-cli tcp redis.localhost.pomerium.io:6379 --listen localhost:6379 &`
  - Run `redis-cli`
- Postgres:
  - Run `pomerium-cli tcp pgsql.localhost.pomerium.io:5432 --listen localhost:5432 &`
  - Run `psql -h localhost -W -U postgres`
  - Log in with password `supersecret`
- ???
- Profit
