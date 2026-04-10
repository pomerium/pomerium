Instructions for debug-oriented Pomerium builds.

# Binary

If you are building a binary to run outside of a container:

```bash
make build-debug
```

That target builds an unoptimized local binary. The debug container images use the normal optimized build and add a troubleshooting toolbox around it.

# Container

The published debug images are toolbox images for shell, DNS, network, TLS, and process inspection.

- `pomerium/pomerium:debug` tracks the latest tagged release.
- `pomerium/pomerium:debug-main` tracks the current `main` branch.
- `debug-v<major>.<minor>` and matching `debug-nonroot` tags track tagged releases.

These images use `debian:bookworm-slim` and include:

- `bash`
- `ca-certificates`
- `curl`
- `dig`, `host`, and `nslookup`
- `ip`, `ping`, and `ss`
- `jq`
- `lsof`
- `nc`
- `openssl`
- `ps`
- `strace`
- `traceroute`

Their entrypoint stays `/bin/pomerium`. These are troubleshooting images, not remote Delve images.

Use `make build-debug` and a local Delve session when you need interactive debugger support.

`strace` needs `SYS_PTRACE` if you want to attach to another running process inside the container.

Root debug variants keep `apt-get` available for additional ad hoc package installs. `debug-nonroot` variants ship the same built-in tools but run as the distroless-compatible nonroot user.

To build the root debug image locally:

```bash
make docker-debug
```
