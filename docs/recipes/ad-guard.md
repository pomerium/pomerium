---
title: AdGuard
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy adguard ad-guard pi-hole piehole
description: >-
  This guide covers how to add authentication and authorization to a hosted, fully, online instance of adguard.
---

# Securing AdGuard Home

This guide covers how to add authentication and authorization to an instance of AdGuard while giving us a great excuse to demonstrate how to use Pomerium's [add headers](../docs/reference/reference.md) functionality to **transparently pass along basic authentication credentials to a downstream app**.

## What is AdGuard?

[AdGuard](https://adguard.com/en/adguard-home/overview.html) Home operates as a DNS server that re-routes tracking domains to a "black hole", thus preventing your devices from connecting to those servers. Instead of browser plugins or other software on each computer, you can install AdGuard in one place and your entire network is protected. AdGuard is very similar to [Pi-hole](https://pi-hole.net) but has some [marked advantages](https://github.com/AdguardTeam/AdGuardHome#comparison).

## Where Pomerium fits

AdGuard is a great candidate for protecting with pomerium as it it does not currently support any authentication or authorization capabilities beyond a single set of [HTTP Basic Access Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) credentials.

## Pre-requisites

This guide assumes you have already completed one of the [quick start] guides, and have a working instance of Pomerium up and running. For purpose of this guide, I'm going to use docker-compose, though any other deployment method would work equally well.

## Configure

### Pomerium Config

```yaml
# config.yaml
- from: https://adguard.domain.example
  to: http://adguard
  allowed_users:
    - user@example.com
  set_request_headers:
    # https://www.blitter.se/utils/basic-authentication-header-generator/
    Authorization: Basic dXNlcjpwYXNzd29yZA===
  allow_websockets: true
```

Here's the important bit. If you don't add the `set_request_headers` line above, you will be prompted for a basic login on each visit.

### Docker-compose

```yaml
# docker-compose.yaml
adguard:
  image: adguard/adguardhome:latest
  volumes:
    - ./adguard/workdir:/opt/adguardhome/work:rw
    - ./adguard/confdir:/opt/adguardhome/conf:rw
  ports:
    - 53:53/udp
  expose:
    - 67
    - 68
    - 80
    - 443
    - 853
    - 3000
  restart: always
```

### Router

![adguard router setup](./img/adguard-router-setup.png)

Set your router to use your new host as the primary DNS server.

### That's it!

Simply navigate to your new adguard instance (e.g. `https://adguard.domain.example`) and behold all of the malware you and your family are no longer subjected to.

![adguard dashboard](./img/adguard-dashboard.png)
