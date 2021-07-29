---
title: TCP Services
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy ssh tcp postgres database redis mysql
description: >-
  This guide covers how to use Pomerium to protect TCP services such as SSH, Postgres and Redis.
---

# Securing TCP based services

The following guide demonstrates how to use Pomerium's [TCP Proxying](/docs/topics/tcp-support.md) support with various TCP services such as databases and other non-HTTP protocols.  It also covers integration points with them when possible.

The source files from this guide can be found on [GitHub](https://github.com/pomerium/pomerium/tree/master/examples/tcp/).

## Background

When replacing a traditional VPN, there are often non-HTTP based applications which must still be reachable.  Pomerium is able to provide the same type of protection to these services by using a client side application to proxy TCP connections.  Authentication and authorization configuration is shared with standard HTTP routes, and the underlying transport is still encrypted between the end-user and Pomerium.

Important notes:

- Pomerium authorizes HTTP on a request-by-request basis, but TCP is authorized on a per-connection basis.
- Pomerium is only authorizing the TCP *connection*. It does not interact with application level authorization systems at this time.

## How it works

* Create a standard Pomerium configuration for your [identity provider (IdP)](/docs/identity-providers/readme.md)
* `pomerium-cli` runs on your workstation, listening on loopback for TCP connections
* When an inbound connection is made, `pomerium-cli` proxies the connection through `pomerium`, authenticating the user if needed
* Pomerium authorizes the connection and forwards it to the upstream service
* The connecting application functions as normal

## Pre-requisites

This recipe is designed to run on a local docker-compose instance. The included configuration can be adopted for any TCP service, however.

* docker
* docker-compose
* A copy of the [example repo](https://github.com/pomerium/pomerium/tree/master/examples/tcp/) checked out
* Valid credentials for your OIDC provider
* The [Pomerium Client](/docs/releases.md#pomerium-cli) installed
* (Optional) `mkcert` to generate locally trusted certificates

## Certificates (optional)

This demo comes with its own certificates, but `pomerium-cli` and your browser will not trust them by default. You may instead provide your own or use [mkcert](https://github.com/FiloSottile/mkcert) to generate locally trusted certificates.

After installing `mkcert`, run the following inside the example repo:

```bash
mkcert -install
   mkcert '*.localhost.pomerium.io'
```

This will install a trusted CA and generate a new wildcard certificate:

- `_wildcard.localhost.pomerium.io.pem`
- `_wildcard.localhost.pomerium.io-key.pem`

To provide your own certificates through another mechanism, please overwrite these files or update `docker-compose.yaml` accordingly.

## Configure

### Pomerium

Update `config.yaml` with your IdP settings and desired policy if adopting for your environment

<<< @/examples/tcp/config.yaml

### Docker Compose

Create a `docker-compose.yaml` file to run Pomerium and, optionally, the services being demonstrated.

Included in our compose file:

- SSH
- Postgres
- Redis

<<< @/examples/tcp/docker-compose.yaml

## Connect

To connect to your service, ensure [`pomerium-cli`](/docs/releases.md#pomerium-cli) is in your `$PATH` and run the `tcp` command, specifying the service you wish to reach.

```bash
pomerium-cli tcp [hostname]:[port]
```

`pomerium-cli` will select a random port on `localhost` by default, but you can specify a port manually if desired.  Keep reading for some specific application examples using the sample `docker-compose.yaml`.

## Redis

```bash
# Start a proxy to redis in the background
% pomerium-cli tcp redis.localhost.pomerium.io:6379 --listen localhost:6379 &
3:01PM INF tcptunnel: listening on 127.0.0.1:6379

# Start the redis client
% redis-cli
3:01PM INF tcptunnel: opening connection dst=redis.localhost.pomerium.io:6379 proxy=redis.localhost.pomerium.io:443 secure=true
3:01PM INF tcptunnel: opening connection dst=redis.localhost.pomerium.io:6379 proxy=redis.localhost.pomerium.io:443 secure=true
3:01PM INF tcptunnel: connection established
127.0.0.1:6379> keys *
 1) "type.googleapis.com/session.Session_last_version"
 2) "type.googleapis.com/user.User"
 3) "type.googleapis.com/session.Session"
 4) "type.googleapis.com/user.User_version_set"
 5) "type.googleapis.com/user.User_last_version"
 6) "server_version_last_version"
 7) "type.googleapis.com/session.Session_version_set"
 8) "server_version_version_set"
 9) "server_version"
10) "type.googleapis.com/directory.User_last_version"```
```

## Postgres

In our example docker-compose, we have configured `supersecret` as the password for the `postgres` user.

```bash
# Start a proxy to postgres in the background
% pomerium-cli tcp pgsql.localhost.pomerium.io:5432 --listen localhost:5432 &
3:07PM INF tcptunnel: listening on 127.0.0.1:5432

# Connect and list the schemas after password authentication
% psql -h localhost -W -U postgres -c '\dn'
Password:
3:06PM INF tcptunnel: opening connection dst=pgsql.localhost.pomerium.io:5432 proxy=pgsql.localhost.pomerium.io:443 secure=true
3:06PM INF tcptunnel: connection established
  List of schemas
  Name  |  Owner
--------+----------
 public | postgres
(1 row)
```

## SSH

SSH clients can make use of external programs to establish a connection to a host.  Most frequently, this is for using an SSH jump host to reach a target system.  However, any transport application can be used.  `pomerium-cli`'s `tcp` command can be used in conjunction with this configuration.  Read on to see how.

More Info:

- [https://man.openbsd.org/ssh_config.5#ProxyCommand](https://man.openbsd.org/ssh_config.5#ProxyCommand)
- [https://www.redhat.com/sysadmin/ssh-proxy-bastion-proxyjump](https://www.redhat.com/sysadmin/ssh-proxy-bastion-proxyjump)

### Setup

To configure your SSH client to use Pomerium's TCP support for SSH routes, create an entry as follows in your `ssh_config` or `~/.ssh/config`:

```
Host *.localhost.pomerium.io
    ProxyCommand pomerium-cli tcp --listen - %h:%p
```

* Be sure to substitute your domain for `localhost.pomerium.io`
* Be sure `pomerium-cli` is in your `$PATH`

### Connecting

That's it!  A Pomerium proxy will be started *automatically* whenever you ssh to a host under `localhost.pomerium.io`.

In our example docker-compose, we have an SSH server configured with `supersecret` as the password for `myuser`.

```bash
% ssh myuser@ssh.localhost.pomerium.io
3:19PM INF tcptunnel: opening connection dst=ssh.localhost.pomerium.io:22 proxy=ssh.localhost.pomerium.io:443 secure=true
3:19PM INF tcptunnel: connection established
myuser@ssh.localhost.pomerium.io's password:
Welcome to OpenSSH Server

5c9f4fa5f5f7:~$
```
