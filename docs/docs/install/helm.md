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

- A Kubernetes provider ([Google Cloud](https://console.cloud.google.com/) for example).
- A configured [identity provider].
- Install [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/).
- Install the [Google Cloud SDK](https://cloud.google.com/kubernetes-engine/docs/quickstart).
- Install [helm](https://helm.sh/docs/using_helm/).
- [TLS certificates].


In addition to sharing many of the same features as the Docker-based quickstart guide, the default helm deployment script also includes a bootstrapped certificate authority enabling mutually authenticated and encrypted communication between services that does not depend on the external LetsEncrypt certificates. Having the external domain certificate de-coupled makes it easier to renew external certificates.

## Configure

1. In your Kubernetes provider, create a new cluster. If you are only installing open-source Pomerium, 1 node would suffice. If you're preparing a configuration for [Pomerium Enterprise](/enterprise/install/helm.md), use at least 3 nodes.

   If you're using Google Cloud, for example, and have the [Google Cloud SDK](https://cloud.google.com/kubernetes-engine/docs/quickstart) installed, you can use the following command. Substitute your preferred region and node count:

   ```bash
   gcloud container clusters create pomerium --region us-west2 --num-nodes 1
   ```

1. Set the context for `kubectl` to your new cluster. <!-- @travis is there a provider-agnostic way to describe this? -->

1. Add Pomerium's Helm repo:

   ```bash
   helm repo add pomerium https://helm.pomerium.io
   ```

1. So that we can create a valid test route, add Bitnami's Helm repo to pull nginx from:

   ```bash
   helm repo add bitnami https://charts.bitnami.com/bitnami
   ```

1. Update Helm:

   ```bash
   helm repo update
   ```

1. Create the Pomerium namespace in your cluster, and set your `kubectl` context to it:

   ```bash
   kubectl create namespace pomerium
   kubectl config set-context --current --namespace=pomerium
   ```

1. Install nginx to the cluster

   ```
   helm upgrade --install nginx bitnami/nginx
   ```



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
