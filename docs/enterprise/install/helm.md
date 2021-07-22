---
title: Helm
sidebarDepth: 1
description: Install Pomerium Enterprise in Kubernetes with Helm
---

# Install Pomerium Enterprise Console in Helm

This document covers installing Pomerium Enterprise Console into your existing helm-managed Kubernetes cluster. 

## Before You Begin

The Pomerium Enterprise Console requires:

- An accessible RDBMS. We support PostgreSQL 9+.
   - A database and user with full permissions for it.
- A certificate management solution. This page will assume a store of certificates using [cert-manager](https://cert-manager.io/docs/) as the solution. If you use another certificate solution, adjust the steps accordingly.
- An existing Pomerium installation. If you don't already have the open-source Pomerium installed in your cluster, see [Pomerium using Helm](/docs/quick-start/helm.md) before you continue.


## System Requirements

For an production deployment, Pomerium Enterprise requires:

### System

- The Pomerium Enterprise Console requires Linux amd64/x86_64. It can manage Pomerium instances on other platforms, however.
- Each Console instance should have at least:
    - 2 vCPUs
    - 8G RAM
    - 100G of disk wherever logs are stored
- Each Postgres instance should have at least:
    - 4 vCPUs
    - 8G RAM
    - 20G for data files
- Each Redis instance should have at least:
    - 2 vCPUs
    - 4G RAM
    - 20G for data files

### Network

- Layer 4 or Layer 7 load balancers to provide high availability across instances of Pomerium Enterprise Console
- Layer 4 or Layer 7 load balancers to provide high availability across instances of the Pomerium Cache service from the console
    - If using Layer 7, your load balancers must support HTTP2
    - DNS RR can be used in place of load balancers, if L4 or HTTP2 support is not possible
- Pomerium Enterprise Console must be able to reach the Pomerium Cache service
- Pomerium Enterprise Console must be able to reach a supported database instance
- Pomerium Proxy service must be able to forward traffic to the Pomerium Enterprise Console

## Certificates

This setup uses [mkcert](https://mkcert.org/) to generate certificates that are trusted by your local web browser for testing, and cert-manager to manage them. If you already have a certificate solution, you can skip the steps below and move on to [the next stage](#configure-kubernetes-for-pomerium). 

### Configure mkcert

1. After [installing mkcert](https://github.com/FiloSottile/mkcert#installation), confirm the presence and names of your local CA files:

   ```bash
   mkcert -install
   The local CA is already installed in the system trust store! 👍
   The local CA is already installed in the Firefox and/or Chrome/Chromium trust store! 👍

   ls $(mkcert -CAROOT)
   rootCA-key.pem  rootCA.pem
   ```


### Install cert-manager

If you haven't already, install cert-manager and create a CA issuer. You can follow their docs listed below, or use the steps provided:

   - [cert-manager: Installing with Helm](https://cert-manager.io/docs/installation/kubernetes/#installing-with-helm)
   - [cert-manager: CA](https://cert-manager.io/docs/configuration/ca/]https://cert-manager.io/docs/configuration/ca/)

1. Create a namespace for cert-manager:

   ```bash
   kubectl create namespace cert-manager
   ```

1. Add the jetstack.io repository and update Helm:

   ```bash
   helm repo add jetstack https://charts.jetstack.io
   helm repo update
   ```

1. Install cert-manager to your cluster:

   ```bash
   helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace \
   --version v1.4.0 --set installCRDs=true
   ```

1. Confirm deployment with `kubectl get pods --namespace cert-manager`:

    ```bash
    kubectl get pods --namespace cert-manager
    NAME                                       READY   STATUS    RESTARTS   AGE
    cert-manager-5d7f97b46d-8g942              1/1     Running   0          33s
    cert-manager-cainjector-69d885bf55-6x5v2   1/1     Running   1          33s
    cert-manager-webhook-8d7495f4-s5s6p        1/1     Running   0          33s
    ```

1. In your Pomerium namespace, create a Kubernetes secret for the rootCA-key file in your local CA root:

   ```bash
   kubectl create secret tls pomerium-tls-ca --namespace=pomerium \
   --cert=$(mkcert -CAROOT)/rootCA.pem --key=$(mkcert -CAROOT)/rootCA-key.pem
   ```

1. Define an Issuer configuration in `issuer.yaml`:

   ```yaml
   apiVersion: cert-manager.io/v1
   kind: Issuer
   metadata:
     name: pomerium-issuer
     namespace: pomerium
   spec:
     ca:
       secretName: pomerium-tls-ca
   ```

1. Apply and confirm:

   ```bash
   kubectl apply -f issuer.yaml
   issuer.cert-manager.io/pomerium-issuer created

   kubectl get issuers.cert-manager.io
   NAME              READY   AGE
   pomerium-issuer   True    5s
   ```

1. Create certificate configurations for Pomerium and Pomerium Enterprise, or just for Enterprise if your existing Pomerium configuration is already configured for TLS encryption:

   - `pomerium-certificates.yaml`

   <<< @/examples/kubernetes/pomerium-certificates.yaml

   ::: tip
   If you already have a public domain configured for your cluster, you can substitute it for `localhost.pomerium.com`.
   :::

   - `pomerium-console-certificates.yaml`

   <<< @/examples/kubernetes/pomerium-console-certificates.yaml

1.  Apply the required certificate configurations, and confirm:

   ```bash
   kubectl apply -f pomerium-certificates.yaml # If open-source Pomerium wasn't already configured for TLS
   kubectl apply -f pomerium-console-certificates.yaml
   ```

   ```bash
   kubectl get certificate
   NAME                    READY   SECRET                 AGE
   pomerium-cert           True    pomerium-tls           10s
   pomerium-console-cert   True    pomerium-console-tls   10s
   pomerium-redis-cert     True    pomerium-redis-tls     10s
   ```

## Configure Kubernetes for Pomerium

If open-source Pomerium was already configured in your Kubernetes cluster, you can skip to the [next step](#update-pomerium)

1. Create the Pomerium namespace, and set your local context to it:

   ```bash
   kubectl create namespace pomerium
   kubectl config set-context --current --namespace=pomerium
   ```

## Update Pomerium

1. Open your helm values file for Pomerium. This document will refer to this file as `pomerium-values.yaml`.

1. Confirm that the `authenticate` block is using the correct TLS secret:

   ```yaml
   authenticate:
     existingTLSSecret: pomerium-tls
   ```

1. In `pomerium-values.yaml`, set `ingress.enabled=false` and define a service block for NodePort:

   ```yaml
   ingress:
     enabled: false
   proxy:
     existingTLSSecret: pomerium-tls
     service:
       type: LoadBalancer
   ```

1. In the `config` block, make sure to set a `sharedSecret`, `cookieSecret`, and `rootDomain`:

   ```yaml
   config:
     existingTLSSecret: pomerium-tls
     sharedSecret: # Shared with the console, you can use "head -c32 /dev/urandom | base64" to create
     cookieSecret: # Shared with the console, you can use "head -c32 /dev/urandom | base64" to create
     rootDomain: appspace.companydomain.com
   ```

   These values are generated by default when not set, but must be explicitly set when configuring Pomerium with Enterprise Console.

1. Also in `config`, set a `policy` block for the Enteprise Console:

   ```yaml
     policy:
       - from: https://console.appspace.companydomain.com
         to: https://pomerium-console.pomerium.svc.cluster.local
         allowed_domains:
           - companydomain.com
         pass_identity_headers: true
   ```

   Remember to adjust the `to` value to match your namespace.

1. Add the `redis` and `databroker` blocks:

   ```yaml
   redis:
     enabled: true
     generateTLS: false
     tls:
       certificateSecret: pomerium-redis-tls
   databroker:
     existingTLSSecret: pomerium-tls
     storage:
       type: redis
   ```

1. Use Helm to update your Pomerium installation:

   ```bash
   helm upgrade --install pomerium pomerium/pomerium --values=./pomerium-values.yaml
   ```

## Install Pomerium Enterprise Console

1. Create `pomerium-console-values.yaml` as shown below, replacing placeholder values:

   ```yaml
   database:
     type: pg
     username: pomeriumDbUser
     password: IAMASTRONGPASSWORDLOOKATME
     host: 198.51.100.53
     name: pomeriumDbName
     sslmode: require
   config:
     sharedSecret: #Shared with Pomerium
     databaseEncryptionKey:  #Generate from "head -c32 /dev/urandom | base64"
     administrators: "youruser@yourcompany.com" #This is a hard-coded access, remove once setup is complete
   tls:
     existingCASecret: pomerium-tls
     caSecretKey: ca.crt
     existingSecret: pomerium-console-tls
     generate: false
   image:
     pullUsername: pomerium/enterprise
     pullPassword: your-access-key
   ```

1. Add the Pomerium Enterprise repository to your Helm configuration:

   ```bash
   helm repo add pomerium-enterprise https://releases.pomerium.com
   helm repo update
   ```

1. Install Pomerium Enterprise:

   ```bash
   helm install pomerium-console pomerium-enterprise/pomerium-console --values=pomerium-console-values.yaml
   ```

## Troubleshooting

### Updating Service Types:

If, while updating the open-source Pomerium values, you change any block's `service.type` you may need to manually delete corresponding service before applying the new configuration. For example:

```bash
kubectl delete svc pomerium-proxy
```
