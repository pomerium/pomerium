---
title: Device Identity
description: >-
  Learn about how WebAuthn is used to authenticate and authorize access using Device ID and state.
sidebarDepth: 1
---

# Device Identity

One of the core components of a zero-trust security model device identity, whereby a device's identity and state can be authenticated and factored into access control decisions. This topic page covers the concept of device identity and how it applies to the zero-trust model.

## Why Device Identity Is Important

The history of IT security has, until recently, mostly focused on user identity verification. In this model, access to a service is granted only after verifying a user's identity and authorization to that service. This was usually sufficient in scenarios where the user's access was physically limited to trusted devices in trusted physical and network spaces; a PC sitting in an office in the company headquarters on a local network, for example.

Device identity is becoming more widely discussed as more products begin to use or require it. For example, Windows 11 generated a lot of news by [requiring TPM 2.0][win11-reqs], and Apple is taking steps to [eliminate passwords][apple-passkeys]:

| ![Verge Article Header and Apple Video Page](./img/verge-apple.png) |
|:--|
| **Sources:**<br />- <https://www.theverge.com/2021/6/25/22550376/microsoft-windows-11-tpm-chips-requirement-security><br/>-  <https://developer.apple.com/videos/play/wwdc2021/10106/> |

Device identity protects a trusted user from accessing sensitive data from a potentially unsafe device, like their personal computer or phone. Think of it as similar to multi-factor authentication (**MFA**); where MFA covers "what you know" (password) and "who you are" (biometrics, face recognition, etc), device identity asks "is this device safe?" by confirming that the device you are using to access a system is trusted.

Device identity is similar but unique to MFA. Where MFA is an additional layer of protection on user identity, Device identity is a unique identifier that asserts trust of the hardware itself.

## What Is Device Identity

> When you remove "the perimeter" as the source of trust to your infrastructure, you must replace it with a level of trust for every person, **device**, and hop in the communication path. Where the other, more commonly implemented facets of zero-trust validates the user and traffic, device identity (through WebAuthn) validates the end user's device.

Device ID is a unique identifying key that can only be created by the specific combination of hardware and software present on a specific device. How this is accomplished is largely dependent on the tools available on the user hardware, which we've detailed below.

### Authenticated Device Types

Device identity is made possible through trusted execution environment (**TEE**) devices that provide a hardware-attested identity. The specific implementation of this general concept is different across the devices that provide device identity, but they generally fall into two categories: secure enclaves and cross-platform security keys.

#### Secure Enclaves

Also called platform or internal authenticators, a secure enclave is physically bound to a specific computing device.

- TPM (Trusted Platform Module): These devices are usually built into a product's mainboard, or can be installed in devices with a TPM header, as shown [here][toms-hardware-tpm]. They include a small processor to carry out cryptographic functions on the device, instead of on the system's processor where it could be interfered with. Trust is usually derived from a private key or certificate signed by a trusted manufacture's certificate authority.

- Mobile devices: Most newer Apple and Android devices include a [Secure Enclave][apple-enclave] or [Hardware-backed Keystore][android-keystore]

#### Hardware Security Keys

Also known as cross-platform or roaming authenticators, these are authentication devices which can move with the user across different computers.

- FIDO U2F: This [open standard][fido-spec] is used by many products like Yubico's [Yubikey][yubikey-products] and Google's [Titan Security Key](https://support.google.com/titansecuritykey/answer/9115487?hl=en). They usually secure a private key used to decrypt information signed by an accessible public key.

::: tip Note
The nature of cross-platform keys mean they are not associated with a single end-user device. Pomerium policies can be written to allow these keys, or specified to only accept secure enclaves.
:::

## Implement Device Identity with Pomerium

Pomerium supports policies that use device identity since version [0.16.0](/docs/upgrading.md#policy-for-device-identity). We use the [Web Authentication][webauthn-api] (**WebAuthN**) API to bring authentication and authorization based on device identity into your security framework. It enables users to register their device ID, and admins to require a trusted device before accessing one, several, or all services.

You can review our implementation of the WebAuthn specification [on GitHub](https://github.com/pomerium/webauthn).

To get started, review the following pages:

- [Pomerium Policy Language](/docs/topcics/ppl.md) to learn how to build policies that use device ID.
- [Enroll a Device](/guides/enroll-device.md) to teach end-users how to enroll devices on Pomerium.


## Looking Ahead: Device Posture

Even if they only use the right device, what happens when a exploit is discovered in their OS or browser? How do you restrict access until the exploit is patched? Expanded iterations of device identity methods account for this using **device posture**, sometimes referred to as device state.

A device state is more complex superset of device identity, with more information about the device and software being used to generate the resulting identifier. This includes the operating system and web browser version. Device posture can be used by secure systems to ensure that users do not access sensitive information using software that has not been updated for, say, a known security flaw.

Designing your security model to use device identity also primes your infrastructure to implement advanced security rules based on device posture down the road.

[android-keystore]: https://source.android.com/security/keystore
[apple-enclave]: https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web
[apple-passkeys]: https://developer.apple.com/documentation/authenticationservices/public-private_key_authentication/supporting_passkeys
[fido-spec]: https://fidoalliance.org/specifications/
[toms-hardware-tpm]: https://www.tomshardware.com/reviews/tpm-trusted-platform-module-header,5766.html
[verge-tpm]: https://www.theverge.com/2021/6/25/22550376/microsoft-windows-11-tpm-chips-requirement-security
[webauthn-api]: https://www.w3.org/TR/webauthn-2/#registration-extension
[win11-reqs]: https://www.microsoft.com/en-us/windows/windows-11-specifications
[yubikey-products]: https://www.yubico.com/products/