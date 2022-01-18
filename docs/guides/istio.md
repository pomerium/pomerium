---
title: Istio
lang: en-US
meta:
  - name: keywords
    content: >-
      pomerium, identity access proxy, istio, traffic management, policy,
      mutual authentication, authorization, kubernetes
description: >-
  Integrate the Pomerium Ingress controller with an Istio service mesh for full mutual authentication in your cluster.
---

# Istio with Pomerium

Istio provides application-aware networking via a service mesh and control plane. When configured with the [Pomerium Ingress Controller] for kubernetes, this enables authorization (**authZ**) and authentication (**authN**) of [east-west traffic] in your internal network bringing you closer to complete [zero trust].

In this guide, we'll demonstrate how to configure Pomerium and Istio in a Kubernetes environment to provide mutual authentication at both the transport and application layer. We'll demonstrate first with a simple test service (Ngix), and then use [Grafana][grafana-guide] to illustrate how the final service can use the same authentication data for user association.

## Before You Begin

- You will need a Kubernetes environment with Istio installed. Refer to their [Getting Started](https://istio.io/latest/docs/setup/getting-started/) guide for more information.
- This configuration uses the Pomerium Ingress Controller for [north-south traffic]. This guide uses our [Helm chart](https://github.com/pomerium/pomerium-helm/tree/master/charts/pomerium) as detailed in [Install Pomerium using Helm]. We'll cover the values needed to configure the controller with an Istio service mesh, but you can refer to the [documentation][Pomerium Ingress Controller] for a complete overview of the controller spec.

## How it Works

In our [Mutual Authentication section on Sidecars](/docs/topics/mutual-auth.md#mutual-authentication-with-a-sidecar), we detail how a single service can offload authN and authz to a sidecar service. In a service mesh, each service in an internal network is provisioned a sidecar, and the controller configures them to provide mutual authentication with each other:

```mermaid
flowchart LR
subgraph pc[Client PC]
  style pc stroke-dasharray: 5 5
  E[Browser]
end
subgraph cluster[Kubernetes Cluster]
  style cluster stroke-dasharray: 5 5
  subgraph spacing[ ]
    style spacing stroke-width:0px,fill:#ffffde;
  end
  subgraph proxy pod
    A[Pomerium Proxy]
    B[Sidecar]
    E--oA
    A-.-B
  end
  subgraph grafana pod
    C[Sidecar]
    D[Grafana]
    C-.-D
    B<==>C
  end
  F[Istio Controller]
  F-.-B
  F-.-C
end
```

::: tip
This is a simplified model that doesn't describe the additional traffic for authorization and authentication.

See the [Legend](/docs/topics/mutual-auth.md#legend) on our Mutual Authentication page for details on our graphing style.
:::

## Configure Pomerium for Istio

Follow [Install Pomerium using Helm] to set up the Pomerium Ingress Controller and Services, with the following adjustments.

1. Apply the appropriate label for Istio injection into your Pomerium namespace:

    ```bash
    kubectl label namespace pomerium istio-injection=enabled
    ```

1. In your `pomerium-values.yaml` file, make the following adjustments for integration with Istio:

    ```yaml
    proxy:
      deployment:
        podAnnotations:
          traffic.sidecar.istio.io/excludeInboundPorts: "80,443" # allow external connections to terminate directly on the Pomerium proxy rather than the sidecar
    config:
      generateTLS: false # disable certificate generation since we offload TLS to the mesh
      insecure: true # disable TLS on internal Pomerium services
    ingress:
      enabled: false # disable the default ingress resource since we are using our ingress controller
    ingressController:
      enabled: true # enable the Pomerium Ingress Controller
    service:
      authorize:
        headless: false # send traffic to the Pomerium Authorize through the Istio service rather than to individual pods
      databroker:
        headless: false # send traffic to the Pomerium Databroker through the Istio service rather than to individual pods
    ```

1. When [defining a test service](/docs/k8s/helm.md#define-a-test-service), you should now see two containers for the service pod:

    ```bash
    kubectl get pods
    NAME                                           READY   STATUS    RESTARTS   AGE
    ...
    nginx-6955473668-cxprp                         2/2     Running   0          19s
    ```

    This indicates that Istio has configured a sidecar container to handle traffic to and from the service.

## Istio CRDs

Now that Pomerium is installed in the cluster, we can define authentication and authorization rules for Istio, which will validate traffic to our example service as coming from the Pomerium Proxy service, through an authorized route, and with an authenticated user token.

1. Adjust the following example `authorization-policy.yaml` file to match your Kubernetes environment and domain names:

    ```yaml
    apiVersion: security.istio.io/v1beta1
    kind: RequestAuthentication
    metadata:
      name: require-pomerium-jwt
    spec:
      selector:
        matchLabels:
          app.kubernetes.io/name: nginx # This matches the label applied to our test service
      jwtRules:
      - issuer: "authenticate.localhost.pomerium.io" # Adjust to match your Authenticate service URL
        audiences:
          - hello.localhost.pomerium.io # This should match the value of spec.host in the services Ingress
        fromHeaders:
          - name: "X-Pomerium-Jwt-Assertion"
        jwksUri: https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json # Adjust to match your Authenticate service URL.
        # The jwksUri key above is the preferred method of retrieving the signing key, and should be used in production. See 
        # See https://istio.io/latest/docs/reference/config/security/jwt/#JWTRule
        #
        #If the Authenticate service is using a localhost or other domain that's not a FQDN. You can instead provide the content from that path using the jwks key:
        #jwks: |
        #  {"keys":[{"use":"sig","kty":"EC","kid":"e1c5d20b9cf771de0bd6038ee5b5fe831f771d3715b72c2db921611ffca7242f","crv":"P-256","alg":"ES256","x":"j8I1I7eb0Imr2pvxRk13cK9ZjAA3VPrdUIHkAslX2e0","y":"jfWNKJkq3b5hrTz2JsrXCcvgJCPP7QSFgX1ZT9wapIQ"}]}
    ---
    apiVersion: security.istio.io/v1beta1
    kind: AuthorizationPolicy
    metadata:
      name: require-pomerium-jwt
    spec:
      selector:
        matchLabels:
          app.kubernetes.io/name: nginx # This matches the label applied to our test service
      action: ALLOW
      rules:
      - when:
        - key: request.auth.claims[aud]
          values: ["hello.localhost.pomerium.io"] # This should match the value of spec.host in the services Ingress
    ```

    This file defines two Custom Resources. The first is a `RequestAuthentication`, and it specifies:
    - For objects with the `app.kubernetes.io/name` label matching `nginx`, Istio will check that:
      - the request includes the header `X-Pomerium-Jwt-Assertion`, which provides a JWT,
      - **and** that JWT is issued by the Pomerium Authenticate service,
      - **and** the JWT is signed by the signing key provided by the Authenticate service.

    If the JWT is found and validated, then the content within can be checked against the `AuthorizationPolicy` below. If the JWT is provided but not validated, it will not pass `RequestAuthentication`. If the JWT is not provided, the request will automatically fail any `AuthorizationPolicy`.


    The second resource is an `AuthorizationPolicy`, and it species:
    - For objects with the `app.kubernetes.io/name` label matching `nginx`, only allow requests:
      - **if** the request includes a JWT (already validated by `RequestAuthentication`) with the audience key `aud`,
      - **and** the value of the `aud` key matches our known route, `hello.localhost.pomerium.io`.

    In other words, `RequestAuthentication` confirms that the incoming traffic to the sidecar has a signed and valid JWT, which confirms that the user has been authenticated and is authorized to access this service. The `AuthorizationPolicy` confirms that the traffic originated from a valid Pomerium route. The latter is especially important in Pomerium Enterprise, where a manager of a separate [Namespace](/enterprise/concepts.md#namespaces) could create a second route to a service normally routed and managed in your namespace.

1. Apply the new resources with `kubectl`:

    ```bash
    kubectl apply -f authorization-policy.yaml
    ```

1. Now when you go to `hello.localhost.pomerium.io` in the browser, you should see `RBAC: access denied`. This confirms that the policy is in place and denying our request. To allow the traffic, add the `pass_identity_headers` annotation to `example-ingress.yaml`:

    ```yaml{7}
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: hello
      annotations:
        cert-manager.io/issuer: pomerium-issuer
        ingress.pomerium.io/pass_identity_headers: "true"
        ingress.pomerium.io/policy: '[{"allow":{"and":[{"domain":{"is":"example.com"}}]}}]'
    ...
    ```

1. After applying the update with `kubectl apply -f example-ingress.yaml`, you should now be able to access the test service in the browser.

## Grafana ini

On the Grafana side we are using the Grafana Helm chart and what follows is the relevant section of the `values.yml` file. The most important thing here is that we need to tell Grafana from which request header to grab the username. In this case that's `X-Pomerium-Claim-Email` because we will be using the user's email (provided by your identity provider) as their username in Grafana. For all the configuration options check out the Grafana documentation about its auth-proxy authentication method.

<<< @/examples/kubernetes/istio/grafana.ini.yml

[Istio]: https://istio.io/latest/
[istio]: https://github.com/istio/istio
[certmanager]: https://github.com/jetstack/cert-manager
[grafana]: https://github.com/grafana/grafana
[grafana-guide]: /guides/grafana.md
[east-west traffic]: https://en.wikipedia.org/wiki/East-west_traffic
[north-south traffic]: https://en.wikipedia.org/wiki/North-south_traffic
[Pomerium Ingress Controller]: /docs/k8s/ingress.md
[zero trust]: /docs/background.md#zero-trust
[Install Pomerium using Helm]: /docs/k8s/helm.md

<!--
- The following example shows how to make Grafana's [auth proxy](https://grafana.com/docs/grafana/latest/auth/auth-proxy) work with Pomerium inside of an Istio mesh.

#### Service Entry For Manually Configured Routes

If you are enforcing mutual TLS in your service mesh you will need to add a ServiceEntry for your identity provider so that Istio knows not to expect a mutual TLS connection with, for example `https://yourcompany.okta.com`.

<<< @/examples/kubernetes/istio/service-entry.yml
 -->