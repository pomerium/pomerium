---
title: Quickstart
sidebarDepth: 1
description: Demo Pomerium Enterprise
---

# Pomerium Enterprise Quickstart

## Before You Begin

This document assumes:

- A non-containerized environment, either your local computer or a virtual machine (**vm**). While Pomerium is designed to scale with your production environment, we'll leave containerization and infrastructure as code (**IaC**) out for now, to focus on learning how Pomerium Enterprise works.
   - `root` or `sudo` privileges on the host.
- You already have the open-source Pomerium base installed. If not, follow [this doc](/docs/install/binary.md) before you continue.
   - While an existing route is not required, we suggest implementing one test route to validate your identity provider (**IdP**) configuration.
- Pomerium Enterprise requires a relational database. PostgreSQL 9+ is supported.
   - Securing the database connection with TLS may not be required, especially for a local installation, but is strongly recommended for production deployments. Therefor, this guide will assume a TLS-secured database connection.
- A supported data broker backend. Currently we support Redis.
   - As with the database, TLS encryption is strongly recommended for production deployments.

## Requirements

- Pomerium Enterprise requires Linux amd64/x86_64. It can manage Pomerium instances on other platforms, however.
- Each Console instance should have at least:
    - 4 vCPUs
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

## Install Pomerium Enterprise

Pomerium publishes standard OS packages for RPM and DEB based systems. The repositories require authentication via username and access key. These credentials will be issued to you during the onboarding process.

:::: tabs

::: tab deb

1. To automatically configure the repository for Debian and Ubuntu distributions, run the following command replacing `[access-key]`:

   ```bash
   curl -1sLf \
   'https://dl.cloudsmith.io/[access-key]/pomerium/enterprise/setup.deb.sh' \
   | sudo -E bash
   ```

   Or to manually configure, you can manually import the apt key, then create a new `.list` file in `/etc/apt/source.list.d`. Make sure to replace the distro and version:

   ```bash
   curl -1sLf 'https://dl.cloudsmith.io/[access-key]/pomerium/enterprise/gpg.B1D0324399CB9BC3.key' | apt-key add -

   echo "deb https://dl.cloudsmith.io/[access-key]/pomerium/enterprise/deb/debian buster main" | sudo tee /apt/sources.list.d/pomerium-console.list
   ```

1. Update `apt` and install Pomerium Enterprise:

   ```bash
   sudo apt update; sudo apt install pomerium-console
   ```

:::


::: tab yum

1. To automatically configure the repository for RHEL based distributions, run the following command replacing `[access-key]`:

   ```bash
   curl -1sLf \
   'https://dl.cloudsmith.io/[access-key]/pomerium/enterprise/setup.rpm.sh' \
   | sudo -E bash
   ```

   Or to manually configure:

   ```bash
   yum install yum-utils pygpgme
   rpm --import 'https://dl.cloudsmith.io/[access-key]/pomerium/enterprise/gpg.B1D0324399CB9BC3.key'
   curl -1sLf 'https://dl.cloudsmith.io/[access-key]/pomerium/enterprise/config.rpm.txt?distro=el&codename=8' > /tmp/pomerium-enterprise.repo
   yum-config-manager --add-repo '/tmp/pomerium-enterprise.repo'
   yum -q makecache -y --disablerepo='*' --enablerepo='pomerium-enterprise'
   ```

1. Update refresh and install:

   ```bash
yum -y install pomerium-console
   ```

:::

::::

### System Service

Once the package is installed, enable and start the system service:

```bash
sudo systemctl enable --now pomerium-console
```

## Initial Configuration

Like the open-source Pomerium base, Pomerium Enterprise is configured through a single config file, located at `/etc/pomerium-console/config.yaml`.


### Update Pomerium

Open your Pomerium config file, `/etc/pomerium/config.yaml`.

1. Add a list item in the `routes` block for the Enterprise Console:

   ```yaml
     routes:
       - from: https://console.localhost.pomerium.com
         to: https://localhost:8701
         policy:
           - allow:
               or:
                 - domain:
                     is: companydomain.com
         pass_identity_headers: true
   ```

   The example value for `to:` assumes Pomerium and Pomerium Enterprise are running on the same test environment.

1. If you haven't already, set `signing_key`. See the [reference page](/reference/readme.md#signing-key) for more information. The same signing key must be used in both Pomerium Core and Enterprise.

   ```yaml
   signing_key: "ZZZZZZZZZZZZZZ"
   ```

1. Define the [databroker](/reference/readme.md#data-broker-service) storage type and connection string. The example below assumes a local Redis server:

   ```yaml
   databroker_storage_type: redis
   databroker_storage_connection_string: redis://127.0.0.1:6379/0
   ```

### External Services

First configure the Console to communicate with the database and databroker service:

```yaml
database_url: pg://user:pass@dbhost.internal.mydomain.com/pomerium?sslmode=require
databroker_service_url: https://pomerium-cache.internal.mydomain.com
shared_secret: XXXXXXXXXXXXXXXXXXX
database_encryption_key: YYYYYYYYYYYYYYYYYYYYYY
```

For database uri options (especially TLS settings) see the [PostgreSQL SSL Support](https://www.postgresql.org/docs/9.1/libpq-ssl.html) documentation.

### Administrators

As a first-time setup step, you must also configure at least one administrator for console access. This user (or users) can then configure additional administrators in the console UI.

```yaml
administrators: you@mydomain.com
```

Once you have set permissions in the console UI, you should remove this configuration.

### TLS, Signing Key and Audience

1. If your open-source Pomerium installation is already configured to use TLS to secure back-end communication, you can do the same for Pomerium Enterprise by providing it a certificate, key, and optional custom CA file to validate the `databroker_service_url` connection:

   ```yaml
   tls_ca_file: /etc/pomerium-console/ca.pem
   tls_cert_file: /etc/pomerium-console/cert.pem
   tls_key_file: /etc/pomerium-console/key.pem
   ```

   For proof-of-concept installations in the same local system, this is not required.

1. Set the [`signing_key`](/enterprise/reference/config.md#signing-key) to match Pomerium's.

1. Set the `audience` key to match the `from` domain value from your [Pomerium configuration](#update-pomerium), excluding protocol:

   ```yaml
   audience: console.localhost.pomerium.com
   ```

   This sets the expected "audience" key in the [JWT header](/reference/readme.md#jwt-claim-headers) to match what's provided by open-source Pomerium as it proxies traffic to the Enterprise Console UI.

Once complete, your `/etc/pomerium-console/config.yaml` file should look something like this:

```yaml
database_url: pg://user:pass@dbhost.internal.mydomain.com/pomerium?sslmode=require
databroker_service_url: https://pomerium-cache.internal.mydomain.com
shared_secret: "XXXXXXXXXXXXXXXXXXX"
database_encryption_key: "YYYYYYYYYYYYYYYYYYYYYY"

# change / remove this after initial setup
administrators: you@mydomain.com

tls_ca_file: /etc/pomerium-console/ca.pem
tls_cert_file: /etc/pomerium-console/cert.pem
tls_key_file: /etc/pomerium-console/key.pem

signing_key: "ZZZZZZZZZZZZZZ"

audience: console.localhost.pomerium.com
```

## Next Steps

Pomerium Enterprise assumes access to a [Prometheus](https://prometheus.io/) data store for metrics. See [Configure Metrics](/enterprise/metrics.md) to learn how to configure access.

## Troubleshooting

### Generate Recovery Token

!!!include(generate-recovery-token.md)!!!