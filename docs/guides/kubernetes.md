---
title: Kubernetes API / Kubectl
lang: en-US
meta:
  - name: keywords
    content: pomerium, identity access proxy, kubernetes, helm, k8s, oauth
description: >-
  This guide covers how to add authentication and authorization to kubernetes api server using single-sign-on and Pomerium.
---

# Securing Kubernetes

The following guide covers how to secure [Kubernetes] using Pomerium. This is achieved by:

- creating a ClusterRoleBinding for a user,
- setting a route through Pomerium to the Kubernetes API server,
- configuring a kubectl context to connect and authorize to the API server through Pomerium.

## Before You Begin

- This guide assumes you've already installed Pomerium in a Kubernetes cluster using our Helm charts. Follow [Pomerium using Helm] before proceeding.
- This guide assumes you have a certificate solution in place, such as Cert-Manager.

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

1. To grant access to users within Kubernetes, you will need to configure role-based access control (**RBAC**) permissions. For example, consider the example below, `rbac-someuser.yaml`:

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

1. Apply the RBAC ClusterRoleBinding:

    ```bash
    kubectl apply -f rbac-someuser.yaml
    ```

Permissions can also be granted to groups the Pomerium user is a member of. This allows you to set a single ClusterRoleBinding in Kubernetes and modify access from your IdP.

## Create a Route for the API server

This new route requires a kubernetes service account token. Our Helm chart creates one and makes it available at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

1. Update your `pomerium-values.yaml` file with the following route:

    ```yaml
      routes:
        - from: https://k8s.localhost.pomerium.io
          to: https://kubernetes.default.svc.cluster.local
          allow_spdy: true
          tls_skip_verify: true
          kubernetes_service_account_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
          policy:
            - allow:
                or:
                  - domain:
                      is: pomerium.com
    ```

    Change the policy to match your configuration.

1. Apply the updated values with Helm:

    ```bash
    helm upgrade --install pomerium pomerium/pomerium --values pomerium-values.yaml
    ```

    This will create a Pomerium route within kubernetes that is accessible from `*.localhost.pomerium.io`.

## Configure Kubectl

The [pomerium-cli] tool can be used by kubectl as a credential plugin. Once configured, connections to the cluster will open a browser window to the Pomerium authenticate service and generate an authentication token that will be used for Kubernetes API calls.


To use `pomerium-cli` as an exec-credential provider, update your kubectl config:

```shell
# Add Cluster
kubectl config set-cluster via-pomerium --server=https://k8s.localhost.pomerium.io
# Add Context
kubectl config set-context via-pomerium --user=via-pomerium --cluster=via-pomerium
# Add credentials command
kubectl config set-credentials via-pomerium --exec-command=pomerium-cli \
  --exec-arg=k8s,exec-credential,https://k8s.localhost.pomerium.io \
  --exec-api-version=client.authentication.k8s.io/v1beta1
```

::: details Skip TLS Verification
If you're using untrusted certificates or need to debug a certificate issue, configure the credential provider without TLS verification:

```shell
kubectl config set-cluster via-pomerium --server=https://k8s.localhost.pomerium.io \
  --insecure-skip-tls-verify=true
kubectl config set-credentials via-pomerium --exec-command=pomerium-cli \
  --exec-arg=k8s,exec-credential,https://k8s.localhost.pomerium.io,--disable-tls-verification \
  --exec-api-version=client.authentication.k8s.io/v1beta1
```
:::

Here's the resulting configuration:

1. Cluster:
    ```yaml
    clusters:
    - cluster:
        server: https://k8s.localhost.pomerium.io
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
           - https://k8s.localhost.pomerium.io
         command: pomerium-cli
         env: null
   ```

With `kubectl` configured you can now query the Kubernetes API via pomerium:

```
kubectl --context=via-pomerium cluster-info
```

You should be prompted to login and see the resulting cluster info.


[kubernetes]: https://kubernetes.io
[pomerium-cli]: /docs/releases.md#pomerium-cli
[Pomerium using Helm]: /docs/k8s/helm.md
