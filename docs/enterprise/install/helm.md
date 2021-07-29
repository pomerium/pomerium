---
title: Helm
sidebarDepth: 1
description: Install Pomerium Enterprise in Kubernetes with Helm
---

# Install Pomerium Enterprise Console in Helm

This document covers installing Pomerium Enterprise Console into your existing helm-managed Kubernetes cluster. It's designed to work with an existing cluster running Pomerium, as described im [Pomerium using Helm]. Follow that document before continuing here.

## Before You Begin

The Pomerium Enterprise Console requires:

- An accessible RDBMS. We support PostgreSQL 9+.
   - A database and user with full permissions for it.
- A certificate management solution. This page will assume a store of certificates using [cert-manager] as the solution. If you use another certificate solution, adjust the steps accordingly.
- An existing Pomerium installation. If you don't already have the open-source Pomerium installed in your cluster, see [Pomerium using Helm] before you continue.


## System Requirements

One of the advantages of a Kubernetes deployment is automatic scaling, but if your database or redis solution is outside of your k8s configuration, refer to the requirements below:

- Each Postgres instance should have at least:
    - 4 vCPUs
    - 8G RAM
    - 20G for data files
- Each Redis instance should have at least:
    - 2 vCPUs
    - 4G RAM
    - 20G for data files

## Issue a Certificate

This setup assumes an existing certificate solution using cert-manager, as described in [Pomerium using Helm]. If you already have a different certificate solution, create and implement a certificate for `pomerium-console.pomerium.svc.cluster.local`. Then you can move on to [the next stage](#update-pomerium).


1. Create a certificate configuration file for Pomerium Enterprise Our example is named `pomerium-console-certificate.yaml`:

   <<< @/examples/kubernetes/pomerium-console-certificate.yaml

1. Apply the required certificate configurations, and confirm:

   ```bash
   kubectl apply -f pomerium-console-certificate.yaml
   ```

   ```bash
   kubectl get certificate
   NAME                    READY   SECRET                 AGE
   pomerium-cert           True    pomerium-tls           92m
   pomerium-console-cert   True    pomerium-console-tls   6s
   pomerium-redis-cert     True    pomerium-redis-tls     92m
   ```

## Update Pomerium

1. Set your local context to your Pomerium namespace:

   ```bash
   kubectl config set-context --current --namespace=pomerium
   ```

1. Open your pomerium values file. If you followed [Pomerium Using Helm], the file is named `pomerium-values.yaml`. In the `config` section, set a `policy` block for the Enterprise Console:

   ```yaml
     policy:
       - from: https://console.localhost.pomerium.com
         to: https://pomerium-console.pomerium.svc.cluster.local
         allowed_domains:
           - companydomain.com
         pass_identity_headers: true
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

1. If you haven't configured a public DNS record for your Pomerium domain space, you can use `kubectl` to generate a local proxy:

   ```bash
   sudo -E kubectl --namespace pomerium port-forward service/pomerium-proxy 443:443
   ```

1. When visiting `https://console.localhost.pomerium.io`, you should se the Session List page:

   ![The Session List page after installing Pomerium Enterprise Console](../img/console-session-landing.png)

## Troubleshooting

### Updating Service Types:

If, while updating the open-source Pomerium values, you change any block's `service.type` you may need to manually delete corresponding service before applying the new configuration. For example:

```bash
kubectl delete svc pomerium-proxy
```

[Pomerium using Helm]: /docs/install/helm.md
[cert-manager]: https://cert-manager.io/docs/