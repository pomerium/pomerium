---
title: Kubernetes / Helm
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc kubernetes Helm reverse-proxy
---

# Pomerium using Helm

This quick-start will show you how to deploy Pomerium with [Helm](https://helm.sh) on [Kubernetes](https://kubernetes.io).

## Prerequisites

- A [Google Cloud Account](https://console.cloud.google.com/).
- A configured [identity provider].
- Install [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/).
- Install the [Google Cloud SDK](https://cloud.google.com/kubernetes-engine/docs/quickstart).
- Install [helm](https://helm.sh/docs/using_helm/).
- [TLS certificates].

Though there are [many ways](https://unofficial-kubernetes.readthedocs.io/en/latest/setup/pick-right-solution/) to work with Kubernetes, for the purpose of this guide, we will be using Google's [Kubernetes Engine](https://cloud.google.com/kubernetes-engine/). That said, most of the following steps should be very similar using any other provider.

In addition to sharing many of the same features as the Kubernetes quickstart guide, the default helm deployment script also includes a bootstrapped certificate authority enabling mutually authenticated and encrypted communication between services that does not depend on the external LetsEncrypt certificates. Having the external domain certificate de-coupled makes it easier to renew external certificates.

## Configure

Download and modify the following helm_gke.sh script and values file to match your [identity provider] and [TLS certificates] settings.

<<<@/examples/helm/helm_gke.sh

<<<@/examples/kubernetes/values.yaml

## Run

Run [./scripts/helm_gke.sh] which will:

1. Provision a new cluster.

1. Create authenticate, authorize, and proxy [deployments](https://cloud.google.com/kubernetes-engine/docs/concepts/deployment).

1. Provision and apply authenticate, authorize, and proxy [services](https://cloud.google.com/kubernetes-engine/docs/concepts/service).

1. Configure an ingress, using Google's default load balancer.

```bash
./scripts/helm_gke.sh
```

## Navigate

Open a browser and navigate to `verify.your.domain.example`.

You can also navigate to the special pomerium endpoint `verify.your.domain.example/.pomerium/` to see your current user details.

![currently logged in user](./img/logged-in-as.png)

[./scripts/helm_gke.sh]: https://github.com/pomerium/pomerium/tree/master/examples
[./scripts/kubernetes_gke.sh]: https://github.com/pomerium/pomerium/tree/master/examples
[example kubernetes files]: https://github.com/pomerium/pomerium/tree/master/examples
[identity provider]: ../identity-providers/readme.md
[letsencrypt]: https://letsencrypt.org/
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
[tls certificates]: ../topics/certificates.md
