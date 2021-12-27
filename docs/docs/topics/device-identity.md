---
title: Device Identity
description: >-
  Learn about how WebAuthn is used to authenticate and authorize access using Device ID and state.
---

## Device Identity

One of the core components of a zero-trust security model is device authentication. Think of it as a component of multi-factor authentication; In addition to "what you know" (password) and "who you are" (biometrics, face recognition, etc), device authentication covers "what you have" by confirming that the device you are using to access a system is trusted.

Device authentication is becoming more widely discussed as more products begin to use or require it. For example, Windows 11 generated a lot of [news stories][verge-tpm] by [requiring TPM 2.0][win11-reqs].

## Authenticated Device Types

Device authentication is made possible through trusted execution environment (**TEE**) devices that provide a hardware-attested identity and state. The specific implementation of this general concept is different across the devices that provide device authentication, but they generally fall into two categories: secure enclaves and cross-platform security keys.

### Secure Enclaves

Also called platform or internal authenticators, a secure enclave is physically bound to a specific computing device.

- TPM (Trusted Platform Module): These devices are usually built in to a product's mainboard, or can be installed in devices with a TPM header, as shown [here][toms-hardware-tpm]. They include a small processor to carry out cryptographic functions on the device, instead of on the system's processor where it could be interfered with. Trust is usually derived from a private key or certificate signed by a trusted manufacture's certificate authority.

- Mobile devices: Most newer Apple and Android devices include a [Secure Enclave][apple-enclave] or [Hardware-backed Keystore][android-keystore]

### Hardware Security Keys

Also known as cross-platform or roaming authenticators, these are authentication devices which can move with the user across different computers.

- FIDO U2F: This [open standard][fido-spec] is used by many products like Yubico's [Yubikey][yubikey-products] and Google's [Titan Security Key](https://support.google.com/titansecuritykey/answer/9115487?hl=en). They usually secure a private key used to decrypt information signed by an accessible public key.

## Device ID and State

Implementation device authentication, regardless of the specific hardware used, provides two pieces of information: device ID and device state.

Device ID is a unique identifying key that can only be created by the specific combination of hardware and software present on a specific device. For example, you will have a different device ID using the same computer with the same security key installed between different operating systems. Even on the same operating system, the device ID will be different when created in different web browsers.

The state is more complex, with more information about the device and software being used to generate the value. This includes the operating system and web browser version. This can be used by secure systems to ensure that users do not access sensitive information using software that has not been updated for, say, a known security flaw.

## WebAuthn

Pomerium uses the [Web Authentication][webauthn-api] (**WebAuthN**) API to bring device authentication into your security framework. It enables users to register their device ID, and admins to require a trusted device before accessing one, several, or all services.

To get started, review the following pages:

- [Pomerium Policy Language](/docs/topcics/ppl.md) to learn how to build policies that use device ID.
- [Enroll a Device](/guides/enroll-device.md) to teach end users how to enroll devices on Pomerium.

[toms-hardware-tpm]: https://www.tomshardware.com/reviews/tpm-trusted-platform-module-header,5766.html
[fido-spec]: https://fidoalliance.org/specifications/
[yubikey-products]: https://www.yubico.com/products/
[win11-reqs]: https://www.microsoft.com/en-us/windows/windows-11-specifications
[verge-tpm]: https://www.theverge.com/2021/6/25/22550376/microsoft-windows-11-tpm-chips-requirement-security
[apple-enclave]: https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web
[android-keystore]: https://source.android.com/security/keystore
[webauthn-api]: https://www.w3.org/TR/webauthn-2/#registration-extension