---
title: TiddlyWiki
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy wiki tiddlywiki
description: >-
  This guide covers how to add authentication and authorization to a hosted, fully, online instance of TiddlyWiki.
---

# Securing TiddlyWiki on Node.js

This guide covers using Pomerium to add authentication and authorization to an instance of [TiddlyWiki on NodeJS](https://tiddlywiki.com/static/TiddlyWiki%2520on%2520Node.js.html).

## What is TiddlyWiki on Node.js

TiddlyWiki is a personal wiki and a non-linear notebook for organizing and sharing complex information. It is available in two forms:

- a single HTML page
- [a Node.js application](https://www.npmjs.com/package/tiddlywiki)

We are using the Node.js application in this guide.

## Where Pomerium fits

TiddlyWiki allows a simple form of authentication by using authenticated-user-header parameter of [listen command](https://tiddlywiki.com/static/ListenCommand.html). Pomerium provides the ability to login with well-known [identity providers](../docs/identity-providers/readme.md#identity-provider-configuration).

## Pre-requisites

This guide assumes you have already completed one of the [quick start] guides, and have a working instance of Pomerium up and running. For purpose of this guide, We will use docker-compose, though any other deployment method would work equally well.

## Configure

### Pomerium Config

```yaml
jwt_claims_headers: email
policy:
- from: https://wiki.example.local
  to: http://tiddlywiki:8080
  allowed_users:
    - reader1@example.com    
    - writer1@example.com    
```
### Docker-compose

<<< @/examples/tiddlywiki/docker-compose.yaml

### That's it

Navigate to your TiddlyWiki instance (e.g. `https://wiki.example.local`) and log in:

* as reader1@example.com: user can read the wiki, but there is no create new tiddler button is show up.

* as writer1@example.com: user can read the wiki and create new tiddlers.

* as another email: pomerium displays a permission denied error.

[quick start]: /docs/install/readme.md
