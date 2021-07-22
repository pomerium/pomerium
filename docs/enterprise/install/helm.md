---
title: Helm
sidebarDepth: 1
description: Install Pomerium Enterprise in Kubernetes with Helm
---

This document covers installing Pomerium Enterprise Console into your existing helm-managed Kubernetes cluster. 

## Before You Begin

The Pomerium Enterprise Console requires:

- An accessible RDBMS. We support PostgreSQL 9+.
   - A database and user with full permissions for it.
- A certificate management solution. This page will assume a store of certificates in <!-- @travis pick a location? --> and assume [cert-manager](https://cert-manager.io/docs/) as the solution. If you use another certificate solution, adjust the steps accordingly.
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

## Update Pomerium

1. Open your helm values file for Pomerium. This document will refer to this file as `pomerium-values.yaml`.

1. In pomerium-values.yaml, remove the `service` block:

   ```diff
   - service:
   -   type: NodePort
   -   ...
   ```


1. Add or modify the `ingress` block to set `enabled: false`:

   ```yaml
   ingress:
     enabled: false
     annotations:
       kubernetes.io/ingress.allow-http: "false"
   ```

1. Add or modify the `proxy` block:

   ```yaml
   proxy:
   service:
      type: LoadBalancer
   tls:
      cert: # base64 encoded TLS certificate
      key: # base64 encoded TLS key
   ```

1. In the `config` block, set a `sharedSecret`, `cookieSecret`, and `rootDomain`:

   ```yaml
   config:
      sharedSecret: # Shared with the console, you can use "head -c32 /dev/urandom | base64" to create
      cookieSecret: # Shared with the console, you can use "head -c32 /dev/urandom | base64" to create
      rootDomain: appspace.companydomain.com
   ```

1. Also in `config`, set a `policy` block for the Enteprise Console:

   ```yaml
     policy:
       - from: https://console.appspace.companydomain.com
         to: https://pomerium-console.default.svc.cluster.local
         allowed_domains:
           - companydomain.com
         pass_identity_headers: true
   ```

1. Add the `redis` and `databroker` blocks:

   ```yaml
   redis:
     enabled: true
   databroker:
     storage:
       connectionString: rediss://pomerium-redis-master.default.svc.cluster.local
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
   enabled: true
   existingCASecret: pomerium-ca-tls 
   caSecretKey: ca.crt #Set to your CA
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


### Disabling Ingress:

After setting `ingress.enabled=false`, you may need to manually delete the `pomerium-proxy` and `pomerium-authenticate` service to update to the new configuration: <!-- @travis I'm sure context could be improved here -->

```bash
kubectl delete svc pomerium-proxy
kubectl delete svc pomerium-authenticate
```

### Updating Redis

<!-- @travis I forget the context here, and it isn't in my history -->

proxy.existingTLSSecret=pomerium-tls. (config after)
