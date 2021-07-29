---
title: Data Storage
sidebarDepth: 3
description: >-
  This article describes Pomerium's data storage requirements
  and backends
---

# Data Storage

## About

#### Background
Pomerium keeps persistent state out of most components, but an identity-aware access proxy must maintain some data about every user's session.  Historically, all user/session related data was stored in cookies, but this quickly became challenging.

- Cookie and header limits would impact large organizations and some IdPs
- SPAs would break when session cookies expired
- No central visibility or management of existing sessions
- Group membership was fixed from session creation
- Slow initial authentication flow to fetch user data

To address these limitations, the Pomerium `databroker` service runs a number of internal services responsible for maintaining data and state.

#### Design

The `databroker` is responsible for providing a stateful storage layer.  Services which require high performance maintain a streaming local cache of the contents of the `databroker`, while others may call `databroker` in real time.  Only the `databroker` is expected to maintain authoritative state.


## Persistence
At this time, most data stored by Pomerium is externally sourced and recoverable at startup (eg, group membership).  The notable exception is user sessions.  If the data hosted by the `databroker` is lost, users will need to log in through their IdP again at next session expiration.

To prevent early session loss in production deployments, persistent storage backends are available for configuration in the `databroker`.  Use of these is strongly encouraged, but smaller or non-production deployments can make use of an in-memory storage layer if external dependencies are not practical or justifiable.

## Backends

Configuration options for each backend are detailed in [databroker configuration reference](/reference/readme.md#data-broker-service).

In all backends, Pomerium encrypts record values.  This ensures security of all records at rest, regardless of data store capabilities.  While this prevents many classes of attack vector, additional security measures should always be taken to secure data in transit and minimize access to the backends themselves.

Please see Pomerium backend and upstream storage system documentation for best practices.

### In-Memory
- Data Broker Service HA: `no`
- Data Store HA: `no`
- Data Persistence: `no`

The default storage backend for `databroker` is memory based.  This backend provides
easy deployment semantics but is not persistent or highly available.  Running more than one `databroker` instance configured for memory backed storage is not supported and will lead to non-deterministic behavior.

### Redis

- Data Broker Service HA: `yes`
- Data Store HA: `yes`
- Data Persistence: `yes`

The Redis based backend supports multiple `databroker` instances and persistence across restarts.  We recommend a dedicated redis instance for Pomerium to provide the strongest security and performance guarantees.

#### High Availability
Redis should be configured to provide high availability via [replication](https://redis.io/topics/replication) and failover.


#### Security
Pomerium supports and strongly encourages [ACL](https://redis.io/topics/acl) based authentication.  To set up an ACL for pomerium, use the following template:

```
ACL setuser pomerium on >[MYPASSWORD] ~* +@all -@scripting -@dangerous -@admin -@connection
```

Pomerium supports and strongly encourages [TLS](https://redis.io/topics/encryption) support in Redis version 6.  Both traditional and mutual TLS are supported.

Example secure configuration:

```yaml
databroker_storage_type: redis
databroker_storage_connection_string: rediss://pomerium:MYSECUREPASSWORD@[HOST]:6379/
databroker_storage_cert_file: /tls/client.pem
databroker_storage_key_file: /tls/client.key
databroker_storage_ca_file: /tls/ca.pem
```

::: tip
the second `s` in `rediss` is intentional and turns on TLS support
:::
