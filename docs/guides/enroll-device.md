---
title: Enroll a Device
lang: en-US
meta:
  - name: keywords
    content: >-
      pomerium, identity access proxy, webauthn, device id, enroll, enrollment,
      authentication, authorization
description: >-
  This guide covers how to enroll a trusted execution environment device as a Pomerium end-user.
---

# Enroll a Device

If a Pomerium route is configured to [require device authentication](/docs/topics/ppl.md#device-matcher), then the user must register a [trusted execution environment](/docs/topics/device-identity.md#authenticated-device-types) (**TEE**) device before accessing the route. Registration is easy, but different depending on the device being used to provide ID.

1. Users are prompted to register a new device when accessing a route that requires device authentication:

    ![The WebAuthn Registration page with no devices registered](./img/webauthn/no-device.png)

    Users can also get to the registration page from the special `.pomerium` endpoint available on any route, at the bottom of the page:

    ![The Device Credentials section of the .pomerium endpoint with the WebAuthn link highlighted](./img/webauthn/device-credentials-empty-highlight.png)

1. Click on **Register New Device**. Your browser will prompt you to provide access to a device. This will look different depending on the browser, operating system, and device type:

    ::::: tabs
    :::: tab Windows
    ![The device authentication prompt on Windows](./img/webauthn/security-key-windows.png)
    ::::
    :::: tab Chrome
    ![The device authentication prompt in Google Chrome](./img/webauthn/security-key-google.png)
    ::::
    :::: tab Firefox
    ![The device authentication prompt in Firefox](./img/webauthn/security-key-firefox.png)
    ::::
    :::: tab ChromeOS
    ![The device authentication prompt on ChromeOS](./img/webauthn/security-key-chromebook.png)
    ::::

## Find Device ID

If a route's policy is configured to only allow specific device IDs you will see a 450 error even after registering:

![450 device not authorized error screen](./img/webauthn/450-error.png)


From the `.pomerium` endpoint you can copy your device ID to provide to your Pomerium administrator.

![Device ID list at /.pomerium](./img/webauthn/device-id-list.png)

From here you can also delete the ID for devices that should no longer be associated with your account.