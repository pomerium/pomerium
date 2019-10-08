---
title: Certificates
lang: en-US
meta:
  - name: keywords
    content: x509 certificates tls mtls letsencrypt lets encrypt
---

# Certificates

[Certificates](https://en.wikipedia.org/wiki/X.509) and [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) play a vital role in [zero-trust][principles] networks, and in Pomerium. This document covers how to generate and set up wild-card certificates suitable for working with pomerium.

This guide uses the following tools and resources:

- [LetsEncrypt](https://letsencrypt.org/about/) is a _public_ certificate authority that issues free certificates trusted by the major browsers. Other [private](https://blog.cloudflare.com/how-to-build-your-own-public-key-infrastructure/) or [public](https://scotthelme.co.uk/are-ev-certificates-worth-the-paper-theyre-written-on/) CAs would also be fine.
- [Google Domains](https://domains.google.com/) registrar will be used to set up our wildcard domain and certificate validation. But any registrar would do and some providers support [automatic renewal](https://github.com/Neilpang/acme.sh/wiki/dnsapi).
- [acme.sh](https://github.com/Neilpang/acme.sh) will be used to retrieve the wild-card domain certificate. Any [LetsEncrypt client](https://letsencrypt.org/docs/client-options/) that supports wildcard domains would work.

It should be noted that there are countless ways of building and managing [public-key infrastructure](https://en.wikipedia.org/wiki/Public_key_infrastructure). And although we hope this guide serves as a helpful baseline for generating and securing pomerium with certificates, these instructions should be modified to meet your own organization's tools, needs, and constraints.

::: warning

LetsEncrypt certificates must be renewed [every 90 days](https://letsencrypt.org/2015/11/09/why-90-days.html).

:::

## Why

Since one of Pomerium's core [principles] is to treat internal and external traffic impartially, Pomerium uses [mutually authenticated TLS](https://en.wikipedia.org/wiki/Mutual_authentication) ubiquitously. For example, Pomerium uses mTLS between:

- end-user and Pomerium
- Pomerium's services **regardless** of if the network is "trusted"
- Pomerium and the destination application

## How

First, you'll want to set a [CNAME](https://en.wikipedia.org/wiki/CNAME_record) record for wild-card domain name you will be using with Pomerium.

![pomerium add a text entry to your dns records](./img/certificate-wildcard-domain.png)

Once you've setup your wildcard domain, we can use acme.sh to create a certificate-signing request with LetsEncrypt.

```bash
# Requires acme.sh @ https://github.com/Neilpang/acme.sh
# Install (after reviewing, obviously) by running :
# $ curl https://get.acme.sh | sh
$HOME/.acme.sh/acme.sh \
    --issue \
    -k ec-256 \
    -d '*.corp.example.com' \
    --dns \
    --yes-I-know-dns-manual-mode-enough-go-ahead-please

Creating domain key
The domain key is here: $HOME/.acme.sh/*.corp.example.com_ecc/*.corp.example.com.key
Single domain='*.corp.example.com'
Getting domain auth token for each domain
Getting webroot for domain='*.corp.example.com'
Add the following TXT record:
Domain: '_acme-challenge.corp.example.com'
TXT value: 'Yz0B1Uf2xjyUI7Cr9-k96P2PQnw3RIK32dMViuvT58s'
Please be aware that you prepend _acme-challenge. before your domain
so the resulting subdomain will be: _acme-challenge.corp.example.com
Please add the TXT records to the domains, and re-run with --renew.
Please check log file for more details: $HOME/.acme.sh/acme.sh.log
Removing DNS records.
Not Found domain api file:
```

LetsEncrypt will respond with the corresponding `TXT` record needed to verify our domain.

![pomerium add a text entry to your dns records](./img/certificate-domain-challenge.png)

It may take a few minutes for the DNS records to propagate. Once it does, you can run the following command to complete the certificate request process.

```bash
# Complete the certificate request now that we have validated our domain
$HOME/.acme.sh/acme.sh \
    --renew \
    --ecc \
    -k ec-256 \
    -d '*.corp.example.com' \
    --dns \
    --yes-I-know-dns-manual-mode-enough-go-ahead-please

Renew: '*.corp.example.com'
Single domain='*.corp.example.com'
Getting domain auth token for each domain
Verifying: *.corp.example.com
Success
Verify finished, start to sign.
Cert success.
-----BEGIN CERTIFICATE-----
.... snip...
-----END CERTIFICATE-----
Your cert is in  $HOME/.acme.sh/*.corp.example.com_ecc/*.corp.example.com.cer
Your cert key is in  $HOME/.acme.sh/*.corp.example.com_ecc/*.corp.example.com.key
The intermediate CA cert is in  $HOME/.acme.sh/*.corp.example.com_ecc/ca.cer
And the full chain certs is there:  $HOME/.acme.sh/*.corp.example.com_ecc/fullchain.cer
```

Here's how the above certificates signed by LetsEncrypt correspond to their respective Pomerium configuration settings:

| Pomerium Config             | Certificate file                                               |
| --------------------------- | -------------------------------------------------------------- |
| [CERTIFICATE]               | `$HOME/.acme.sh/*.corp.example.com_ecc/fullchain.cer`          |
| [CERTIFICATE_KEY]           | `$HOME/.acme.sh/*.corp.example.com_ecc/*.corp.example.com.key` |
| [CERTIFICATE_AUTHORITY]     | `$HOME/.acme.sh/*.corp.example.com_ecc/ca.cer`                 |
| [OVERRIDE_CERTIFICATE_NAME] | `*.corp.example.com`                                           |

Your end users will see a valid certificate for all domains delegated by Pomerium.

![pomerium valid certificate](./img/certificates-valid-secure-certificate.png)

![pomerium certificates A+ ssl labs rating](./img/certificates-ssl-report.png)

## Resources

Certificates, TLS, and Public Key Cryptography is a vast subject we cannot adequately cover here so if you are new to or just need a brush up, the following resources may be helpful:

- [Why HTTPS for Everything?](https://https.cio.gov/everything/) The US government's CIO office has an excellent guide covering HTTPS and why future government sites will all be HTTPS.
- [Is TLS Fast](https://istlsfastyet.com/) debunks the performance myth associated with HTTPS.
- [Use TLS](https://smallstep.com/blog/use-tls.html) covers why TLS should be used everywhere; not just for securing typical internet traffic but for securing service communication in both "trusted" and adversarial situations.
- [Everything you should know about certificates and PKI but are too afraid to ask](https://smallstep.com/blog/everything-pki.html)

[certificate]: ../reference/#certificate
[certificate_authority]: ../reference/#certificate-authority
[certificate_key]: ../reference/#certificate-key
[override_certificate_name]: ../reference/#override-certificate-name
[principles]: ../docs/#why
[zero-trust]: ../docs/#why
