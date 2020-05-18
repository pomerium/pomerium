---
title: Helm
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc kubernetes Helm reverse-proxy
---

# Pomerium using Helm

This quick-start will show you how to deploy Pomerium with [Helm](https://helm.sh) on [Kubernetes](https://kubernetes.io).

## Prerequisites

- A [Google Cloud Account](https://console.cloud.google.com/)
- A configured [identity provider]
- Install [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- Install the [Google Cloud SDK](https://cloud.google.com/kubernetes-engine/docs/quickstart)
- Install [helm](https://helm.sh/docs/using_helm/)
- [TLS certificates]

Though there are [many ways](https://unofficial-kubernetes.readthedocs.io/en/latest/setup/pick-right-solution/) to work with Kubernetes, for the purpose of this guide, we will be using Google's [Kubernetes Engine](https://cloud.google.com/kubernetes-engine/). That said, most of the following steps should be very similar using any other provider.

In addition to sharing many of the same features as the Kubernetes quickstart guide, the default helm deployment script also includes a bootstrapped certificate authority enabling mutually authenticated and encrypted communication between services that does not depend on the external LetsEncrypt certificates. Having the external domain certificate de-coupled makes it easier to renew external certificates.

## Configure

Download and modify the following helm_gke.sh script and values file to match your [identity provider] and [TLS certificates] settings.

<<<@/docs/configuration/examples/helm/helm_gke.sh

<<<@/docs/configuration/examples/kubernetes/values.yaml

## Run

Run [./scripts/helm_gke.sh] which will:

1. Provision a new cluster.
2. Create authenticate, authorize, and proxy [deployments](https://cloud.google.com/kubernetes-engine/docs/concepts/deployment).
3. Provision and apply authenticate, authorize, and proxy [services](https://cloud.google.com/kubernetes-engine/docs/concepts/service).
4. Configure an ingress, Google's default load balancer.

```bash
./scripts/helm_gke.sh
```

## Navigate

Open a browser and navigate to `httpbin.your.domain.example`.

You can also navigate to the special pomerium endpoint `httpbin.your.domain.example/.pomerium/` to see your current user details.

![currently logged in user](./img/logged-in-as.png)

[./scripts/helm_gke.sh]: ../reference/examples.html#helm
[./scripts/kubernetes_gke.sh]: ../reference/examples.html#google-kubernetes-engine
[example kubernetes files]: ../reference/examples.html#google-kubernetes-engine
[identity provider]: ../identity-providers/readme.md
[letsencrypt]: https://letsencrypt.org/
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
[tls certificates]: ../reference/certificates.md
