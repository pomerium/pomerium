---
title: $SERVICE
description: Tunnel $SERVICE connections through Pomerium
layout: Draft
---

# Tunneled $SERVICE Connections

This is a template to standardize how we document connections to popular services through a Pomerium TCP tunnel. It's not listed in the site map, so if you're not a Pomerium employee and you're reading this, you're either looking at our open-source code base, or... ¯\_(ツ)_/¯

Replace the paragraph above with a brief description of the service, and/or why you would want to tunnel traffic to it.

::: tip
This example assumes you've already [created a TCP route](/docs/tcp/readme.md#configure-routes) for this service.
:::

 ## Basic Connection

 1. Create a TCP tunnel, using either [`pomerium-cli`](/docs/releases.md#pomerium-cli) or the Pomerium Desktop client:

    ::::: tabs
    :::: tab pomerium-cli
    ```bash
    pomerium-cli tcp aService.corp.example.com:$COMMON-PORT --listen :$ANOTHER-PORT
    ```

    :::tip --listen
    The `--listen` flag is optional. It lets you define what port the tunnel listens on locally. If not specified, the client will choose a random available port.
    :::

    ::::
    :::: tab Pomerium Desktop
    \![An example connection to a $SERVICE service from Pomerium Desktop](./img/desktop/example-$SERVICE-connection.png) <!-- Remove the escape \ -->

    :::tip Local Address
    The **Local Address** field is optional. Using it defines what port the tunnel listens on locally. If not specified, Pomerium Desktop will choose a random available port.
    :::

    ::::
    :::::

1. Initiate your $SERVICE connection, pointing to `localhost`:

    ```bash
    $COMMAND
    ```
    Optionally, if the service is accessed through GUI software, include a screenshot here. If both are commonly used, show both using tabs.

## Tunnel and Connect Simultaneously

If $COMMAND has a method of initiating the `pomerium-cli` tunnel as it attempts to connect, document it here.

## Always Tunnel through Pomerium

If the client software can be configured to automatically initiate a `pomerium-cli` tunnel when connecting, document that here.

## More Resources

Always include at least one or two links in a bulleted list that could help the reader.