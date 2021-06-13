# Overview

This section contains applications, and scenario specific guides for Pomerium.

- The [ad-guard](./ad-guard.md) recipe demonstrates how pomerium can be used to augment web applications that only support simplistic authorization mechanisms like basic-auth with single-sign-on driven access policy.
- The [argo](./argo.md) guide demonstrates how pomerium can be used to add access control to [Argo](https://argoproj.github.io/projects/argo).
- The [Cloud Run](./cloud-run.md) recipe demonstrates deploying pomerium to Google Cloud Run as well as using it to Authorize users to protected Cloud Run endpoints.
- The [JWT Verification](./jwt-verification.md) guide demonstrates how to verify the Pomerium JWT assertion header using Envoy.
- The [Kubernetes Dashboard](./kubernetes-dashboard.md) guide covers how to secure Kubernetes dashboard using Pomerium.
- The [kubernetes](./kubernetes.md) guide covers how to add authentication and authorization to kubernetes dashboard using helm, and letsencrypt certificates. This guide also shows how third party reverse-proxies like nginx/traefik can be used in conjunction with pomerium using forward-auth.
- The [local OIDC](./local-oidc.md) guide demonstrates how pomerium can be used with local OIDC server for dev/testing.
- The [mTLS](./mtls.md) guide demonstrates how pomerium can be used to add mutual authentication using client certificates and a custom certificate authority.
- The [TiddlyWiki](./tiddlywiki.md) guide demonstrates how pomerium can be used to add authentication and authorization to web application using authenticated header.
- The [visual studio code](./vs-code-server.md) guide demonstrates how pomerium can be used to add access control to third-party applications that don't ship with [fine-grained access control](https://github.com/cdr/code-server/issues/905).
- The [Transmission](./transmission.md) guide demonstrates how Pomerium can act as an authentication and authorization proxy for your Transmission daemon's RPC interface, which only provides unencrypted HTTP auth out of the box.
