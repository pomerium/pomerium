# Remote dev containers

## What

These are configurations for Visual Studio Code telling it how to create or access a development container with a well-defined tool and runtime stack.

Basically, this allows us to run VS Code from within a container, remotely.

## Why

Integrating, testing, and debugging Pomerium behind other fronting proxies (nginx/traefik) in forward-auth configuration is a real pain. In particular, it is difficult to do step debugging inside a containerized environment where part of that environment lives outside the network stack of the other components.

It turns out that bringing the debug environment to the containerized environment is easier than bringing the request flow.

## How

- Install [Remote-container](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
- run `Remote-Containers: Rebuild Container` from the Command Palette
- ???
- Debug, code, etc as your normally would.
