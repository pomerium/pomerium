---
title: TCP Support
description: >-
  This article describes how to leverage pomerium for TCP proxying
meta:
  - name: keywords
    content: pomerium pomerium-cli proxy identity-access-proxy ssh tcp postgres database redis mysql application non-http
---

# TCP Support

## About

Operations and engineering teams frequently require access to lower level administrative and data protocols such as SSH, RDP, Postgres, MySQL, Redis, etc.

In addition to managing HTTP based applications, Pomerium can be used to protect non-HTTP systems with the same consistent authorization policy. This is achieved by tunneling TCP over HTTP with the help of a client side command built into [`pomerium-cli`](/docs/releases.md#pomerium-cli).


Internally, Pomerium uses the [`CONNECT` method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT) to establish the TCP tunnel.

::: warning
To minimize issues with TCP support, Pomerium should not be placed behind another HTTP proxy.  Instead, configure your load balancer in L4 or TCP mode.

Otherwise, the HTTP proxy in front of Pomerium must know how to properly handle the `CONNECT` command and proxy it upstream.  This capability will be specific to each proxy implementation.
:::

## Configuring

TCP configuration is simple. Just specify the correct scheme and ports in your route [`to`](/reference/readme.md#to) and [`from`](/reference/readme.md#from) fields.

Example:
```yaml
routes:
  - from: tcp+https://redis.corp.example.com:6379
    to: tcp://redis.internal.example.com:6379
    policy:
    - allow:
        or:
          - email:
              is: contractor@not-example.com
          - groups:
              has: ["datascience@example.com"]
```

Notes:

* When configuring a TCP route, any HTTP specific settings such as `regex_rewrite_pattern`, or `set_request_headers` have no effect.
* While data is encrypted from a user system to Pomerium's proxy, the underlying application protocol must also support encryption for data to be fully encrypted end-to-end.
* The ports in `from` and `to` are independent.  Users only need to know the `from` URL to connect.  The `to` can be changed without end user participation.

## Using

While HTTP routes can be consumed with just a normal browser, `pomerium-cli` must serve as a proxy for TCP routes.  It is [available](/docs/releases.md#pomerium-cli) for a variety of platforms in various formats.

To connect, you normally need just the external hostname and port of your TCP route:

```bash
% pomerium-cli tcp redis.corp.example.com:6379
5:57PM INF tcptunnel: listening on 127.0.0.1:52046
```

By default, `pomerium-cli` will start a listener on loopback on a random port.

On first connection, you will be sent through a standard Pomerium HTTP authentication flow.  After completing this, your TCP connection should be established!

```bash
% redis-cli -h localhost -p 52046
localhost:52046> keys *
(empty array)
localhost:52046>
```

## Advanced Usage

### Listen Configuration

You may specify an optional address and port for the `tcp` command to listen on.

`-` specifies that STDIN and STDOUT should be directly attached to the remote TCP connection.  This is useful for [SSH](#ssh-helper-configuration) or for sending data through a shell pipe.

### SSH Helper Configuration

A sample SSH ProxyCommand configuration in `ssh_config`:

```
Host *.corp.example.com
    ProxyCommand ~/bin/pomerium-cli tcp --listen - %h:%p
```

A sample SSH command using `pomerium-cli` as a ProxyCommand:

```bash
ssh -o ProxyCommand='pomerium-cli tcp --listen - %h:%p' ssh.localhost.pomerium.io
```

More information on SSH ProxyCommand:

- [https://man.openbsd.org/ssh_config.5#ProxyCommand](https://man.openbsd.org/ssh_config.5#ProxyCommand)
- [https://www.redhat.com/sysadmin/ssh-proxy-bastion-proxyjump](https://www.redhat.com/sysadmin/ssh-proxy-bastion-proxyjump)

### Custom URL

If the Pomerium proxy is not reachable through port `443` or the route is not in external DNS, a custom URL may be specified:

```bash
% pomerium-cli tcp --pomerium-url https://pomerium.corp.example.com:8443 redis.corp.example.com:6379
```

The above command connects to `https://pomerium.corp.example.com:8443` and then requests the TCP route named `redis.corp.example.com:6379`.
