---
title: Quickstart
sidebarDepth: 1
description: Demo Pomerium Enterprise
---

# Pomerium Enterprise Quickstart

## Before You Begin

This guide document:

- A non-containerized environment, either your local computer or a virtual machine (**vm**). While Pomerium is designed to scale with your production environment, we'll leave containerization and infrastructure as code (**IaC**) out for now, to focus on learning how Pomerium Enterprise works.
   - `root` or `sudo` privileges on the host.
- You already have the open-source Pomerium base installed. If not, follow [this doc](/docs/quick-start/binary.md) before you continue.
   - While an existing route is not required, we suggest implementing one test route to validate your identity provider (**IdP**) configuration.
- Pomerium Enterprise requires a relational database. PostgreSQL 9+ and MySQL 5.8+ are supported.
   - Securing the database connection with TLS may not be required, especially for a local installation, but is strongly recommended for production deployments. Therefor, this guide will assume a TLS-secured database connection.
- A supported data broker backend. Currently we support Redis.
   - As with the database, TLS encryption is strongly recommended for production deployments.

## Requirements

For a proof-of-concept local or vm installation, we suggest:

<!-- @travis what specs? -->

## Install Pomerium Enterprise Console

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

1. Update `apt` and install the Pomerium Enterprise Console:

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
   need to confirm the RHEL commands here
   ```

:::

::::

### System Service

Once the package is installed, enable and start the system service:

```bash
sudo systemcrt enable --now pomerium-console
```

## Initial Configuration

Like the open-source Pomerium base, the Pomerium Enterprise Console is configured through a single config file, located at `/etc/pomerium-console/config.yaml`.

### External Services

First configure the Console to communicate with the database and databroker service:

```yaml
database_url: pg://user:pass@dbhost.internal.mydomain.com/pomerium?sslmode=require
databroker_service_url: https://pomerium-cache.internal.mydomain.com
shared_secret: XXXXXXXXXXXXXXXXXXX
database_encryption_key: YYYYYYYYYYYYYYYYYYYYYY
```

For database uri options (especially TLS settings) see the documentation of your particular database driver:

 - [PostgreSQL SSL Support](https://www.postgresql.org/docs/9.1/libpq-ssl.html)

 - [MySQL Connector/ODBC Connection Parameters](https://dev.mysql.com/doc/connector-odbc/en/connector-odbc-configuration-connection-parameters.html)

### Administrators

As a first-time setup step, you must also configure at least one administrator for console access. This user (or users) can then configure additional administrators in the console UI.

```yaml
administrators: [you@mydomain.com](mailto:you@mydomain.com)
```

Once you have set permissions in the console UI, you should remove this configuration.

### TLS

Communication between the Pomerium Enterprise Console and Pomerium Core components should always be secured via TLS. You should provide a certificate and key for the console service and may optionally provide a custom CA to verify the *`databroker_service_url`* connection:

```yaml
tls_ca_file: /etc/pomerium-console/ca.pem
tls_cert_file: /etc/pomerium-console/cert.pem
tls_key_file: /etc/pomerium-console/key.pem
```


Once complete, your `/etc/pomerium-console/config.yaml` file should look something like this:

```yaml
database_url: pg://user:pass@dbhost.internal.mydomain.com/pomerium?sslmode=require
databroker_service_url: https://pomerium-cache.internal.mydomain.com
shared_secret: XXXXXXXXXXXXXXXXXXX
database_encryption_key: YYYYYYYYYYYYYYYYYYYYYY

# change / remove this after initial setup
administrators: you@mydomain.com

tls_ca_file: /etc/pomerium-console/ca.pem
tls_cert_file: /etc/pomerium-console/cert.pem
tls_key_file: /etc/pomerium-console/key.pem
```
