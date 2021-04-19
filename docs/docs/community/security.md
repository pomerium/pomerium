---
title: Security
lang: en-US
sidebarDepth: 0
meta:
  - name: keywords
    content: pomerium security disclosure vulnerabilities
---

# Security Policy

## Security & Threat model

As a context-aware access proxy, Pomerium's security model holds data confidentiality, integrity, accountability, authentication, authorization, and availability as the highest priority concerns. This page outlines Pomerium's security goals and threat model.

Pomerium's threat model includes:

- **Validating authentication.** Though not itself an Identity Provider, Pomerium incorporates Single-Sign-On flow with third party providers to delegate authentication, and populate identity details for authorization decisions. Pomerium ensures that a request is backed by a valid user session from a trusted Identity Provider.
- **Enforcing authorization.** Pomerium ensures that only authorized users can access services, or applications to which they are entitled access.

  - For HTTP based services, authorization will be made on a per request basis.
  - Otherwise, for TCP based services, authorization will be made on a per session basis.

- **Protecting data in transit**. All communication is encrypted and mutually authenticated when certificates are provided. This applies to communication between:

  - Pomerium and its services.
  - Pomerium and upstream services and applications.
  - Pomerium and downstream clients (e.g. user's browser or device).
  - Pomerium and the databroker's storage system.

- **Protecting data at rest**. Sensitive data is encrypted. This applies to all data in the databroker including:

  - Session, user, and directory data; as well as any other identity or contextual data.
  - Service secrets (TLS certificates, Identity provider credentials)

- **Ensuring availability**. Pomerium aims to be fault tolerant, and horizontally scalable. Pomerium inherits [Envoy's availability threat model](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/threat_model#confidentiality-integrity-and-availability).

- **Providing auditability and accountability**. Pomerium provides logs with associated context for auditing purposes.

Pomerium's threat model does not include:

- Protecting against arbitrary control of a trusted third-party provider. For instance, if your identity provider is hacked, an attacker can impersonate a user in Pomerium.
- Protecting against memory analysis of a running Pomerium instance. If an attacker can attach a debugger to a running instance of Pomerium, they can inspect confidential data in flight.
- Protecting against arbitrary control of the storage backend. If an attacker controls your database, they can corrupt data.
- Protecting an upstream application's internal access control system.
- Protecting against physical access.

### Cryptography

Pomerium uses cryptography to secure data in transit, at rest, and to provide guarantees around confidentiality, authenticity, and integrity between its services and upstreams it manages access for.

Encryption at rest:

- Confidential data stored at rest is encrypted using the [authenticated encryption with associated data](https://en.wikipedia.org/wiki/Authenticated_encryption) construction [XChaCha20-Poly1305](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction) with 196-bit nonces. Nonces are randomly generated for every encrypted object. When data is read, the authentication tag is checked for tampering.

Encryption in transit:

- Data in transit is protected by Transport Layer Security ([TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security)) . See our lab's [SSL Labs report](https://www.ssllabs.com/ssltest/analyze.html?d=authenticate.demo.pomerium.com&latest) .

  - The minimum accepted version of TLS is 1.2.
  - For TLS 1.3, the following cipher suites are offered:

    - TLS_AES_128_GCM_SHA256
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256

  - For TLS 1.2, the following cipher suites are offered, in this order:

    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

  - The following elliptic curves are offered, in this order:

    - X25519
    - secp256r1
    - X448
    - secp521r1
    - secp384r1

- [HTTP Strict Transport Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) (HSTS) with a long duration is used by default.

- [Mutually authenticated](https://en.wikipedia.org/wiki/Mutual_authentication) TLS is used when client side certificates are provided.

## Receiving Security Updates

The best way to receive security announcements is to subscribe to the [pomerium-announce](https://groups.google.com/g/pomerium-announce) mailing list. Any messages pertaining to a security issue will be prefixed with [security].

## Disclosure Process

In general, Pomerium follows [Go's security policy](https://golang.org/security) and uses the following disclosure process:

1. Once the security report is received it is assigned a primary handler. This person coordinates the fix and release process.
2. The issue is confirmed and a list of affected software is determined.
3. Code is audited to find any potential similar problems.
4. Fixes are prepared for the most recent major releases and the head/master revision.
5. When the fixes are applied, announcements are sent to [pomerium-announce](https://groups.google.com/g/pomerium-announce).

This process can take some time. Every effort will be made to handle the bug in as timely a manner as possible, however it's important that we follow the process described above to ensure that disclosures are handled consistently.

## Reporting a Security Bug

If you believe you've found a security vulnerability in Pomerium, please notify us; we will work with you to resolve the issue promptly. Thank you for helping to keep Pomerium and our users safe! We deeply appreciate any effort to discover and disclose security vulnerabilities responsibly.

All security bugs in Pomerium should be reported by email to security@pomerium.com . Your email will be acknowledged within 48 hours, and you'll receive a more detailed response to your email within 72 hours indicating the next steps in handling your report.

While researching, we'd like you to refrain from:

- Any form of Denial of Service (DoS)
- Spamming
- Social engineering or phishing of Pomerium employees or contractors
- Any attacks against Pomerium's physical property or data centers

We may revise these guidelines from time to time. The most current version of the guidelines will be available at <https://pomerium.com/docs/community/security>.

Though we accept PGP-encrypted email, please only use it for critical security reports.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org
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
ZDRB+exOyJJypi2cSaarxiI2gaMT2wp+dChnQ4k=
=LGUI
-----END PGP PUBLIC KEY BLOCK-----
```
