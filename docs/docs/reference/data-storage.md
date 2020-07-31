---
title: Data Storage
description: >-
  This article describes Pomerium's data storage requirements
  and backends
---

# Data Storage

## About

### Background
Pomerium keeps persistent state out of most components, but a identity-aware access proxy on the modern
internet has the need to readily access data that is not always available in a performant or friendly way.  Historically,
all user related data was stored in cookies, but this quickly became challenging.  

- Cookie and header limits would impact large organizations and some IdPs
- SPAs would break when session cookies expired
- No central visibility or management of existing sessions
- Group membership was fixed from session creation

To address these limitations, the `cache` service runs a number of internal services responsible for maintaining data and state.  

### Design

Internal to the `cache` service, the `databroker` is responsible for providing a stateful storage layer.  Services
which require high performance maintain a streaming local cache of the contents of the `databroker`, while others may call `databroker` 
in real time.  Only the `databroker` is expected to maintain authoritative state.


### Persistence
At this time, most data stored by Pomerium is externally sourced and recoverable at startup (eg, group membership).  The notable exception is user 
sessions.  If the data hosted by the `databroker` is lost, users will need to log in through their IdP again at next session expiration.  

To prevent early session loss in production deployments, persistent storage backends are available for configuration in the `databroker`.  Use of these is strongly encouraged, but smaller or non-production deployments can make use of an in-memory storage layer if external dependencies are not practical or justifiable.

## Backends

### In-Memory

The default storage backend for `databroker` is memory based.  This backend provides
easy deployment semantics but is not persistent or highly available.  Running more than one `cache` instance configured for memory backed storage is not supported and will lead to non-deterministic behavior.

### Redis

The Redis based backend supports multiple `cache` instances and persistence across restarts.  We recommend a dedicated redis instance for Pomerium to make 

#### HA
Redis is expected to provide high availability via [replication](https://redis.io/topics/replication) and address failover.


#### Security
Pomerium supports and strongly encourages [TLS](https://redis.io/topics/encryption) support in Redis version 6.  Both traditional and mutual TLS are supported.  Example:

```yaml
XXXX
```

Pomerium supports and strongly encourages [ACL](https://redis.io/topics/acl) based authentication.  To set up an ACL for pomerium, use the following template:

```
ACL setuser pomerium on >[MYPASSWORD] ~* +@all -@scripting -@dangerous -@admin -@connection
```





