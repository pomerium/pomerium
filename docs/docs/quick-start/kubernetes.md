---
title: Kubernetes
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc kubernetes reverse-proxy
---

# Pomerium using Kubernetes

This quickstart will cover how to deploy Pomerium with Kubernetes. Though there are [many ways](https://kubernetes.io/docs/setup/pick-right-solution/) to work with Kubernetes, for the purpose of this guide, we will use Google's [Kubernetes Engine](https://cloud.google.com/kubernetes-engine/). That said, most of the following steps should be very similar using any other provider.

## Prerequisites

- A configured [identity provider]
- A [wild-card TLS certificate]
- A [Google Cloud Account](https://console.cloud.google.com/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- [Google Cloud SDK](https://cloud.google.com/kubernetes-engine/docs/quickstart)

## Download

Retrieve the latest copy of pomerium's source-code by cloning the repository.

```bash
git clone https://github.com/pomerium/pomerium.git $HOME/pomerium
cd $HOME/pomerium/docs/docs/reference/examples/kubernetes
```

## Configure

Edit [./kubernetes_gke.sh] making sure to change the identity provider secret value to match your [identity provider] and [wild-card tls certificate] settings.

<<<@/docs/docs/reference/examples/kubernetes/kubernetes_gke.sh

## Run

Run [./kubernetes_gke.sh] which will:

1. Provision a new cluster.
2. Create authenticate, authorize, and proxy [deployments](https://cloud.google.com/kubernetes-engine/docs/concepts/deployment).
3. Provision and apply authenticate, authorize, and proxy [services](https://cloud.google.com/kubernetes-engine/docs/concepts/service).
4. Configure an ingress load balancer.

```bash
cd $HOME/pomerium/docs/docs/reference/examples/kubernetes
sh ./kubernetes_gke.sh
```

You should see roughly the following in your terminal. Note, provisioning does take a few minutes.

[![asciicast](https://asciinema.org/a/223821.svg)](https://asciinema.org/a/223821)

And if you check out Google's Kubernetes Engine dashboard you'll see something like:

![Google's Kubernetes Engine dashboard](./img/kubernetes-gke.png)

## Navigate

Open a browser and navigate to `httpbin.your.domain.example`.

[./kubernetes_gke.sh]: ../reference/examples#google-kubernetes-engine
[example kubernetes files]: ../reference/examples#google-kubernetes-engine
[identity provider]: ../identity-providers/readme.md
[letsencrypt]: https://letsencrypt.org/
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
[wild-card tls certificate]: ../reference/certificates.md
