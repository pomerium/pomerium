---
title: Kubernetes
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy kubernetes helm k8s oauth
description: >-
  This guide covers how to add authentication and authorization to kubernetes apiserver using single-sing-on and pomerium.
---

# Securing Kubernetes

The following guide covers how to secure [Kubernetes] using Pomerium.

## Kubernetes

This tutorial uses an example Kubernetes cluster created with [`kind`](https://kind.sigs.k8s.io/docs/user/quick-start/). First create a config file (`kind-config.yaml`):

```yaml
# kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30443
        hostPort: 30443
```

Next create the cluster:

```bash
kind create cluster --config=./kind-config.yaml
```

### Pomerium Service Account

Pomerium uses a single service account and user impersonatation headers to authenticate and authorize users in Kubernetes. To create the Pomerium service account use the following config: (`pomerium-k8s.yaml`)

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

Apply it with:

```bash
kubectl apply -f ./pomerium-k8s.yaml
```

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

## Certificates

For this tutorial we will generate wildcard certificates for the `*.localhost.pomerium.io` domain using [`mkcert`](https://github.com/FiloSottile/mkcert):

```bash
mkcert '*.localhost.pomerium.io'
```

This creates two files:

- `_wildcard.localhost.pomerium.io-key.pem`
- `_wildcard.localhost.pomerium.io.pem`

## Pomerium

### Configuration

Our Pomerium configuration will route requests from `k8s.localhost.pomerium.io:30443` to the kube-apiserver. Create a Kubernetes YAML configuration file (`pomerium.yaml`):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: default
  name: pomerium
  labels:
    app: pomerium
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pomerium
  template:
    metadata:
      labels:
        app: pomerium
    spec:
      containers:
        - name: pomerium
          image: pomerium/pomerium:master
          ports:
            - containerPort: 30443
          env:
            - name: ADDRESS
              value: "0.0.0.0:30443"
            - name: AUTHENTICATE_SERVICE_URL
              value: "https://authenticate.localhost.pomerium.io:30443"
            - name: CERTIFICATE
              value: "..." # $(base64 -w 0 <./_wildcard.localhost.pomerium.io.pem)
            - name: CERTIFICATE_KEY
              value: "..." # $(base64 -w 0 <./_wildcard.localhost.pomerium.io-key.pem)
            - name: COOKIE_SECRET
              value: "..." # $(head -c32 /dev/urandom | base64 -w 0)
            - name: IDP_PROVIDER
              value: google
            - name: IDP_CLIENT_ID
              value: "..."
            - name: IDP_CLIENT_SECRET
              value: "..."
            - name: POLICY
              value: "..." #$(echo "$_policy" | base64 -w 0)

---
apiVersion: v1
kind: Service
metadata:
  namespace: default
  name: pomerium
spec:
  type: NodePort
  selector:
    app: pomerium
  ports:
    - port: 30443
      targetPort: 30443
      nodePort: 30443
```

Make sure to fill in the appropriate values as indicated.

The policy should be a base64-encoded block of yaml:

```yaml
- from: https://k8s.localhost.pomerium.io:30443
  to: https://kubernetes.default.svc
  tls_skip_verify: true
  allowed_domains:
    - pomerium.com
  kubernetes_service_account_token: "..." #$(kubectl get secret/"$(kubectl get serviceaccount/pomerium -o json | jq -r '.secrets[0].name')" -o json | jq -r .data.token | base64 -d)
```

Applying this configuration will create a Pomerium deployment and service within kubernetes that is accessible from `*.localhost.pomerium.io:30443`.

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
   kubectl config set-credentials via-pomerium --exec-command=pomerium-cli --exec-args=k8s,exec-credential,https://k8s.localhost.pomerium.io:30443
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
