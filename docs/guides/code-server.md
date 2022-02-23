---
title: code-server
lang: en-US
meta:
  - name: keywords
    content: >-
      pomerium, identity access proxy, visual studio code,
      authentication, authorization, code server, vscode, coder, codercom
description: >-
  This guide covers how to add authentication and authorization to a hosted,
  fully, online instance of visual studio code.
---

# Securing Visual Studio Code Server

## Background

This guide covers using Pomerium to secure an instance of [code-server]. Pomerium is an identity-aware access proxy that can add single-sign-on / access control to any service, including Visual Studio Code.

### Visual Studio Code

[Visual Studio Code] is an open source code editor by Microsoft that has become [incredibly popular](https://insights.stackoverflow.com/survey/2019#technology-_-most-popular-development-environments) in the last few years. For many developers, [Visual Studio Code] hits the sweet spot between no frills editors like vim/emacs and full feature IDE's like Eclipse and IntelliJ. VS Code offers some of the creature comforts like intellisense, git integration, and plugins, while staying relatively lightweight.

One of the interesting attributes of [Visual Studio Code] is that it is built on the [Electron](https://en.wikipedia.org/wiki/Electron_(software_framework)) framework which uses a headless instance of Chrome rendered as a desktop application. It didn't take long for folks to realize that if we already had this great IDE written in Javascript, it may be possible to make [Visual Studio Code] run remotely.

> "Any application that can be written in JavaScript, will eventually be written in JavaScript." -- [Jeff Atwood](https://blog.codinghorror.com/the-principle-of-least-power/)

### code-server

[code-server] is an open-source project that allows you to run [Visual Studio Code] on a **remote** server, through the browser. For example, this is a screenshot taken at the end of this tutorial.

![visual studio code with pomerium](./img/vscode-pomerium.png)

## Pre-requisites

This guide assumes you have already completed one of the [install] guides, and have a working instance of Pomerium up and running. For purpose of this guide, we'll use [Docker Compose](https://docs.docker.com/compose/), though any other deployment method would work equally well.

## Configure

### Add A Route

Define a route in your Pomerium configuration file:

```yaml

routes:
  - from: https://code.corp.example.com
    to: http://codeserver:8080
    policy:
      - allow:
          or:
            - email:
                is: user@example.com
    allow_websockets: true
```

In this example route, `code.corp.example.com` is the publicly accessible route for the route, and `codeserver` is the local hostname for the server or container running code-server.

### Docker Compose

In the `services` section of your `docker-compose.yaml` file, add a block for code-server:

```yaml
services:
  codeserver:
    image: codercom/code-server:latest
    restart: always
    ports:
      - 8080:8080
    volumes:
      - ./code-server:/home/coder/project
    command: --auth none --disable-telemetry /home/coder/project
```

### Apply and Test

1. Bring up your new code-server container. If you're already running your containers with Docker Compose in detached mode, you can apply changes with `docker-compose up -d`.

1. After saving your Pomerium configuration file, you may need to restart the docker Pomerium docker container. This is caused by issues with Docker recognizing timestamp updates for files in volume mounts.

1. Navigate to your domain (e.g. `https://code.corp.domain.example`).

    ![visual studio code pomerium hello world](./img/vscode-helloworld.png)

## Develop Pomerium in Pomerium (Example)

As a final touch, now that we've done all this work we might as well use our new development environment to write some real, actual code. And what better project is there than Pomerium? 😉

1. To build Pomerium, we must [install go](https://golang.org/doc/install) which is as simple as running the following commands in the [integrated terminal] :

    ```bash
    # install dependencies with apt
    sudo apt-get update && sudo apt-get install -y wget make zip

    # download go
    wget https://golang.org/dl/go1.16.4.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.16.4.linux-amd64.tar.gz
    ```

1. Add Go to our [PATH] :

    ```bash
    # add the following to $HOME/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    export PATH=$PATH:$(go env GOPATH)/bin
    ```

1. Reload [PATH] by opening the [integrated terminal] and sourcing the updated `.bashrc` file:

    ```bash
    source $HOME/.bashrc
    ```

1. Now that we've got Go all we need to go is grab the latest source and build:

    ```bash
    # get the latest source
    git clone https://github.com/pomerium/pomerium.git

    # build pomerium
    cd pomerium
    make build
    # run pomerium!
    ./bin/pomerium --version
    # v0.14.0-28-g38a75913+38a75913
    ```

Happy remote hacking!!!😁

:::tip

When the code-server container is rebuilt, any files outside of `/home/coder/project` are reset, removing any dependencies (such as go and make). In a real remote development workflow, you could mount additional volumes, or [use a custom code-server container](https://github.com/cdr/deploy-code-server/tree/main/deploy-container) with these dependencies installed.

:::

[integrated terminal]: https://code.visualstudio.com/docs/editor/integrated-terminal
[path]: https://en.wikipedia.org/wiki/PATH_(variable)
[install]: /docs/install/readme.md
[synology nas]: /guides/synology.md
[visual studio code]: https://code.visualstudio.com/
[code-server]: https://github.com/cdr/code-server
