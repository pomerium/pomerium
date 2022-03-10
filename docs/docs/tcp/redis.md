---
title: Redis
description: Tunnel Redis connections through Pomerium
---

# Tunneled Redis Connections

Redis is a popular in-memory data structure store. It can be run locally or configured as a single or distributed standalone service.

::: tip
This example assumes you've already [created a TCP route](/docs/tcp/readme.md#configure-routes) for this service.
:::

## Basic Connection

 1. Create a TCP tunnel, using either [`pomerium-cli`](/docs/releases.md#pomerium-cli) or the Pomerium Desktop client:

    ::::: tabs
    :::: tab pomerium-cli
    ```bash
    pomerium-cli tcp redis.corp.example.com:6379 --listen :6379
    ```

    :::tip --listen
    The `--listen` flag is optional. It lets you define what port the tunnel listens on locally. If not specified, the client will choose a random available port.
    :::

    ::::

    :::: tab Pomerium Desktop
    ![An example connection to a Redis service from Pomerium Desktop](./img/desktop/example-redis-connection.png)
    :::tip Local Address
    The **Local Address** field is optional. Using it defines what port the tunnel listens on locally. If not specified, Pomerium Desktop will choose a random available port.
    :::

    ::::
    :::::

1. Initiate your Redis connection, pointing to `localhost`:

    ```bash
    redis-cli -h localhost -p 6379
    ```

This demonstrates access to a Redis server through Pomerium from the `redis-cli` tool. Pomerium Enterprise users can utilize [Service Accounts](/enterprise/reference/configure.md#service-accounts) to enable secure machine-to-machine communication of Redis services.

## More Resources

- [redis-cli](https://redis.io/topics/rediscli)
- [Redis ACL](https://redis.io/topics/acl)