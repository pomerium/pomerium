---
title: Kubernetes API / Kubectl
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy kubernetes helm k8s oauth
description: >-
  This guide covers how to add authentication and authorization to kubernetes apiserver using single-sing-on and pomerium.
---

# Securing Kubernetes

The following guide covers how to secure [Kubernetes] using Pomerium.

## Before You Begin

- This guide assumes you've already installed Pomerium in a Kubernetes cluster using our Helm charts. Follow [Pomerium using Helm](/docs/install/helm.md) before proceeding.
- This guide assumes you have a certificate solution in place, such as Cert-Manager.
- As with our Helm-based install instructions, this guide assumes you're using the Pomerium Ingress Controller to handle traffic in and out of the cluster. Routes will be defined as Ingresses.

### Pomerium Service Account

Pomerium uses a single service account and user impersonation headers to authenticate and authorize users in Kubernetes. This service account is automatically created by our Helm chart. If you've installed Pomerium without our charts, expand below to manually create the service account.

::: details Manually create service account

To create the Pomerium service account use the following configuration file: (`pomerium-k8s.yaml`)

```yaml
# pomerium-k8s.yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  namespace: default
  name: pomerium
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pomerium-impersonation
rules:
  - apiGroups:
      - ""
    resources:
      - users
      - groups
      - serviceaccounts
    verbs:
      - impersonate
  - apiGroups:
      - "authorization.k8s.io"
    resources:
      - selfsubjectaccessreviews
    verbs:
      - create
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pomerium
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pomerium-impersonation
subjects:
  - kind: ServiceAccount
    name: pomerium
    namespace: default
```

Apply the configuration with:

```bash
kubectl apply -f ./pomerium-k8s.yaml
```

:::

### User Permissions

To grant access to users within Kubernetes, you will need to configure RBAC permissions. For example:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-admin-crb
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: someuser@example.com
```

Permissions can also be granted to groups the Pomerium user is a member of.

## Create an Ingress for the API Server

Create an Ingress for the route to the Kubernetes API server:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: k8s
  annotations:
    cert-manager.io/issuer: pomerium-issuer
    ingress.pomerium.io/policy: '[{"allow":{"and":[{"domain":{"is":"pomerium.com"}}]}}]'
    ingress.pomerium.io/secure_upstream: true
    ingress.pomerium.io/allow_spdy: true
spec:
  ingressClassName: pomerium
  rules:
  - host: k8s.localhost.pomerium.io
    http:
      paths:
      - backend:
          service:
            name: kubernetes.default.svc
            port:
              number: 30443
  tls:
  - hosts:
    - k8s.localhost.pomerium.io
    secretName: k8s.localhost.pomerium.io-tls

```

::: details Non-Ingress Route

If you're not using the Pomerium Ingress Controller, you will need to define a standard route. The route should be a base64-encoded block of yaml:

```yaml
- from: https://k8s.localhost.pomerium.io:30443
  to: https://kubernetes.default.svc
  tls_skip_verify: true
  allow_spdy: true
  policy:
    - allow:
        or:
          - domain:
              is: pomerium.com
  kubernetes_service_account_token: "..." #$(kubectl get secret/"$(kubectl get serviceaccount/pomerium -o json | jq -r '.secrets[0].name')" -o json | jq -r .data.token | base64 -d)
```

:::

Applying this configuration change will create a Pomerium route within kubernetes that is accessible from `*.localhost.pomerium.io:30443`.

## Kubectl

Pomerium uses a custom Kubernetes exec-credential provider for kubectl access. This provider will open up a browser window to the Pomerium authenticate service and generate an authorization token that will be used for Kubernetes API calls.

The Pomerium Kubernetes exec-credential provider can be installed via go-get:

```bash
env GO111MODULE=on GOBIN=$HOME/bin go get github.com/pomerium/pomerium/cmd/pomerium-cli@master
```

Make sure `$HOME/bin` is on your path.

To use the Pomerium Kubernetes exec-credential provider, update your kubectl config:

   ```shell
   # Add Cluster
   kubectl config set-cluster via-pomerium --server=https://k8s.localhost.pomerium.io:30443
   # Add Context
   kubectl config set-context via-pomerium --user=via-pomerium --cluster=via-pomerium
   # Add credentials command
   kubectl config set-credentials via-pomerium --exec-command=pomerium-cli --exec-arg=k8s,exec-credential,https://k8s.localhost.pomerium.io:30443
  ```

Here's the resulting configuration:

1. Cluster:
    ```yaml
    clusters:
    - cluster:
        server: https://k8s.localhost.pomerium.io:30443
      name: via-pomerium
    ```

2. Context:

   ```yaml
   contexts:
   - context:
       cluster: via-pomerium
       user: via-pomerium
     name: via-pomerium
   ```

3. User:

   ```yaml
   - name: via-pomerium
     user:
       exec:
         apiVersion: client.authentication.k8s.io/v1beta1
         args:
           - k8s
           - exec-credential
           - https://k8s.localhost.pomerium.io:30443
         command: pomerium-cli
         env: null
   ```

With `kubectl` configured you can now query the Kubernetes API via pomerium:

```
kubectl --context=via-pomerium cluster-info
```

You should be prompted to login and see the resulting cluster info.


[kubernetes]: https://kubernetes.io
