Instructions for remotely debugging pomerium.  Especially useful in container deployments.

- [Building](#building)
  - [Binary](#binary)
  - [Container](#container)
- [Running](#running)
  - [Kubernetes](#kubernetes)
  - [Docker Compose](#docker-compose)
- [Debugging](#debugging)
  - [VSCode](#vscode)

# Building

## Binary

If you are building a binary to run outside of a container:

```
make build-debug
```

## Container

The published `pomerium/pomerium:debug` image contains an entrypoint and environment appropriate for debugging purposes.  It can be run in docker by itself, or in kubernetes.  It will not run the debugger by default - set the entrypoint to `/debug-entrypoint.sh`.

It can be rebuilt via:

`docker build -t pomerium/pomerium:debug -f Dockerfile.debug .`

# Running

To run the container in debug mode you must:

- Set your entrypoint to `/debug-entrypoint.sh`
- Add the `SYS_PTRACE` capability
- Attach your debugger to the `dlv` port (9999 by default)

Override `DEBUG_PORT` or `DEBUG_ADDRESS` env vars to change listening ports and addresses.

## Kubernetes

Patch your deployment as follows:

patch.yaml
```yaml
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: pomerium
        # this can be changed in helm chart or use a custom/local build
        image: pomerium/pomerium:debug
        securityContext:
          capabilities:
            add:
            - SYS_PTRACE
        command:
        - /debug-entrypoint.sh
        # Disable health checks
        livenessProbe: null
        readinessProbe: null
```

Patch the deployment:

```bash
kubectl patch deployments.apps pomerium-authorize --patch "$(cat patch.yaml)"
```

Port forward to the service:

```bash
DEPLOYMENT=pomerium-authorize
kubectl port-forward $(kubectl get pods -l app.kubernetes.io/name=${DEPLOYMENT} -o jsonpath="{.items[0].metadata.name}") 9999
```

## Docker Compose

Set/override the following parameters in your compose file:

```yaml
services:
    pomerium:
        entrypoint: /debug-entrypoint.sh
        cap_add:
            - SYS_PTRACE
        ports:
            - "9999:9999"

```

# Debugging

## VSCode

Use remote debugging support.  Set up a launch configuration as follows:


**NOTE** The remotePath must precisely match the directory the code was built in.  See references: [1] [2].  The directory does not need to actually exist in the running container.

```json
    {
      "name": "Connect to server",
      "type": "go",
      "request": "attach",
      "mode": "remote",
      "remotePath": "/go/src/github.com/pomerium/pomerium/",
      "port": 9999,
      "host": "127.0.0.1",
    }
```

Running the launch configuration should attach to the running process.


[1]: https://github.com/microsoft/vscode-go/issues/941
[2]: https://github.com/microsoft/vscode-go/issues/2010
