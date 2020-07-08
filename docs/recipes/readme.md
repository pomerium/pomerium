# Overview

This section contains applications, and scenario specific guides for Pomerium.

- The [ad-guard](./ad-guard.md) recipe demonstrates how pomerium can be used to augment web applications that only support simplistic authorization mechanisms like basic-auth with single-sign-on driven access policy.
- The [kubernetes](./kubernetes.md) guide covers how to add authentication and authorization to kubernetes dashboard using helm, and letsencrypt certificates. This guide also shows how third party reverse-proxies like nginx/traefik can be used in conjunction with pomerium using forward-auth.
- The [visual studio code](./vs-code-server.md) guide demonstrates how pomerium can be used to add access control to third-party applications that don't ship with [fine-grained access control](https://github.com/cdr/code-server/issues/905).
- The [argo](./argo.md) guide demonstrates how pomerium can be used to add access control to [Argo](https://argoproj.github.io/projects/argo).
- The [mTLS](./mtls.md) guide demonstrates how pomerium can be used to add mutual authentication using client certificates and a custom certificate authority.
- The [local OIDC](./local-oidc.md) guide demonstrates how pomerium can be used with local OIDC server for dev/testing.
