---
title: Ingress Controller
lang: en-US
sidebarDepth: 1
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc kubernetes Ingress reverse-proxy
---

# Kubernetes Ingress Controller

Use Pomerium as a first class secure-by-default Ingress Controller. Dynamically provision routes from Ingress resources and set policy based on annotations.

TODO: Funfact: you can dynamically create and remove routes with OSS Pomerium using the Ingress Controller, which you can't do otherwise.

## Prerequisites

- A certificate management solution. If you do not already have one in place, this article covers using Cert Manager.
- A Redis backend with high-persistence is highly recommended.

::: tip
TODO: CloudRun endpoints can be easily supported using "internal traffic policy", if they are deployed to the same cloud project as Pomerium. 
:::

### System Requirements

- Kubernetes v0.19.0+
- Pomerium [Helm Chart](https://github.com/pomerium/pomerium-helm/tree/master/charts/pomerium) v25.0.0+

### Limitations

::: warning
Only one Ingress Controller instance/replica is supported per Pomerium cluster.
:::

## Installation

### Helm

Our instructions for [Installing Pomering Using Helm](/docs/k8s/helm.md) includes the Ingress Controller as part of the documented configuration.

TODO: @travisgroth what else do we need to say about this?

```yaml
ingressController:
  enabled: true
```

### Docker Image

You may deploy your own manifests by using the `pomerium/ingress-controller` docker image.

## Configuration

TODO: Describe where and how these flags are used.


|  Flag                          | Description                                                          |
| ------------------------------ | -------------------------------------------------------------------- |
| `--databroker-service-url`     | the databroker service url
| `--databroker-tls-ca`          | base64 encoded tls CA
| `--databroker-tls-ca-file`     | tls CA file path for the databroker connection connection
| `--health-probe-bind-address`  | The address the probe endpoint binds to. (default ":8081")
| `--metrics-bind-address`       | The address the metric endpoint binds to. (default ":8080") 
| `--name`                       | IngressClass controller name (default "pomerium.io/ingress-controller")
| `--namespaces`                 | namespaces to watch, or none to watch all namespaces
| `--prefix`                     | Ingress annotation prefix (default "ingress.pomerium.io")
| `--shared-secret`              | base64-encoded shared secret for communicating with databroker
| `--update-status-from-service` | update ingress status from given service status (pomerium-proxy)|

The helm chart exposes a subset of these flags for appropriate customization.

TODO: Extrapolate on ^

## Usage

### Defining Routes

If you've tested Pomerium using the all-in-one service, you're probably familiar with configuring routes in Pomerium's `config.yaml`. In this environmenzt, each route is defined as a.... what @travis?

TODO: Finish ^

The Ingress Controller will monitor Ingress resources in the cluster, creating a Pomerium route definition for each one.  Policy and other configuration options for the route are set by using annotations starting with `ingress.pomerium.io/`.

Example:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    ingress.pomerium.io/policy: '[{"allow":{"and":[{"email":{"is":"user@yourdomain.com"}}]}}]' # This can also be a yaml block quote
spec:
  rules:
  - host: hello.localhost.pomerium.io
    http:
      paths:
      - backend:
          service:
            name: nginx-hello
            port:
              name: http
        path: /
        pathType: Prefix
```

Becomes:

```yaml
routes:
  - from: https://hello.localhost.pomerium.io 
    to: http://nginx-hello.default.svc.cluster.local
    policy:
    - allow:
        and:
          - email:
              is: user@yourdomain.com
```


### Supported Annotations

The following annotations behave the same as described in our reference documentation (each one is linked to the appropriate section):

- [`cors_allow_preflight`]
- [`allow_public_unauthenticated_access`]
- [`allow_any_authenticated_user`]
- [`timeout`]
- [`idle_timeout`]
- [`allow_websockets`]
- [`set_request_headers`]
- [`remove_request_headers`]
- [`set_response_headers`]
- [`rewrite_response_headers`]
- [`preserve_host_header`]
- [`pass_identity_headers`]
- [`tls_skip_verify`]
- [`tls_server_name`]
- [`allowed_users`]
- [`allowed_groups`]
- [`allowed_domains`]
- [`allowed_idp_claims`]
- [`policy`]
- [`health_checks`]
- [`outlier_detection`]
- [`lb_config`]

The remaining annotations are specific to or behave differently in this context:

| Annotation              | Description |
| ----------------------- | ------------------------------------------------------------------------------------------- |
| `tls_custom_ca_secret`                    | Name of Kubernetes `tls` Secret containing a custom [CA certificate][`tls_custom_ca_secret`] for the upstream
| `tls_client_secret`                       | Name of Kubernetes `tls` Secret containing a [client certificate][`tls_client_secret`] for connecting to the upstream
| `tls_downstream_client_ca_secret`         | Name of Kubernetes `tls` Secret containing a [Client CA][`tls_downstream_client_ca_secret`] for validating downstream clients
| `secure_upstream`                         | When set to true, use `https` when connecting to the upstream endpoint.
	
::: tip
Every value for the annotations above must be in `string` format.
:::

### Cert Manager Integration

TODO: @travisgroth

## HTTPS endpoints

The `Ingress` spec defines that all communications to the service should happen in cleartext. Pomerium supports HTTPS endpoints, including mTLS.

TODO: Link to Ingress spec ref doc.

Annotate your `Ingress` with

```yaml
ingress.pomerium.io/secure_upstream: true
```

Additional TLS may be supplied by creating a Kubernetes secret(s) in the same namespaces as `Ingress` resource. Note we do not support file paths or embedded secret references.

- [`tls_client_secret`](https://pomerium.io/reference/#tls-client-certificate)
- [`tls_custom_ca_secret`](https://pomerium.io/reference/#tls-custom-certificate-authority)
- [`tls_downstream_client_ca_secret`](https://pomerium.io/reference/#tls-downstream-client-certificate-authority)

Note the referenced `tls_client_secret` must be a [TLS Kubernetes secret](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets). `tls_custom_ca_secret` and `tls_downstream_client_ca_secret` must contain `ca.crt` containing a .PEM encoded (Base64-encoded DER format) public certificate.


### External services

You may refer to external services by defining a `Service` with `externalName`. 

I.e. if you have `https://my-existing-service.corp.com`:


```yaml
apiVersion: v1
kind: Service
metadata:
  name: external
spec:
  type: ExternalName
  externalName: "my-existing-service.corp.com"
  ports:
    - protocol: TCP
      name: https
      port: 443
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: external
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod-http
    ingress.pomerium.io/secure_upstream: "true"
    ingress.pomerium.io/policy: |
      - allow:
          and:
            - domain:
                is: pomerium.com
spec:
  ingressClassName: pomerium
  tls:
    - hosts:
        - "external.localhost.pomerium.io"
      secretName: external-localhost-pomerium.io
  rules:
    - host: "external.localhost.pomerium.io"
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: external
                port:
                  name: https
```

## Troubleshooting

### View Event History

Pomerium Ingress Controller will add **events** to the ingress objects as it processes them.

```
kubectl describe ingress/my-ingress
```

```log
Events:
  Type    Reason   Age   From              Message
  ----    ------   ----  ----              -------
  Normal  Updated  18s   pomerium-ingress  updated pomerium configuration
```

If an error occurs, it may be reflected in the events:

```log
Events:
  Type     Reason       Age                 From              Message
  ----     ------       ----                ----              -------
  Normal   Updated      5m53s               pomerium-ingress  updated pomerium configuration
  Warning  UpdateError  3s                  pomerium-ingress  upsert routes: parsing ingress: annotations: applying policy annotations: parsing policy: invalid rules in policy: unsupported conditional "maybe", only and, or, not, nor and action are allowed
```

### HSTS

If your domain has [HSTS] enabled and you visit an endpoint while Pomerium is using the self-signed bootstrap certificate or a LetsEncrypt staging certificate (before cert-manager has provisioned a production certificate), the untrusted certificate may be pinned in your browser and need to be reset. See [this article](https://www.ssl2buy.com/wiki/how-to-clear-hsts-settings-on-chrome-firefox-and-ie-browsers) (external link) for more information.

TODO: ^ replaces the sentence below. Confirm it has all needed info.

If your domain has HSTS enabled, and you visit i.e. _authenticate_ endpoint while Pomerium is using self-signed bootstrap certificate, or i.e. LetsEncrypt staging certificate, before cert-manager provisioned a production certificate, it may get pinned in your browser and need be reset.

https://www.ssl2buy.com/wiki/how-to-clear-hsts-settings-on-chrome-firefox-and-ie-browsers

## More Information

For more information on the Pomerium Ingress Controller or the Kubernetes concepts discussed, see:

- [Ingress (Kubernetes Docs)](https://kubernetes.io/docs/concepts/services-networking/ingress/)
- [Pomerium Helm Chart README: Pomerium Ingress Controller](https://github.com/travisgroth/pomerium-helm/tree/master/charts/pomerium#pomerium-ingress-controller)
- [Pomerium Kubernetes Ingress Controller (code repository)](https://github.com/pomerium/ingress-controller)

[HSTS]: https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
[`cors_allow_preflight`]: /reference/#cors-allow-preflight
[`allow_public_unauthenticated_access`]: /reference/#allow-public-unauthenticated-access
[`allow_any_authenticated_user`]: /reference/#allow_any_authenticated_user
[`timeout`]: /reference/#timeout
[`idle_timeout`]: /reference/#idle-timeout
[`allow_websockets`]: /reference/#allow-websockets
[`set_request_headers`]: /reference/#set-request-headers
[`remove_request_headers`]: /reference/#remove-request-headers
[`set_response_headers`]: /reference/#set-response-headers
[`rewrite_response_headers`]: /reference/#rewrite-response-headers
[`preserve_host_header`]: /reference/#preserve-host-header
[`pass_identity_headers`]: /reference/#pass-identity-headers
[`tls_skip_verify`]: /reference/#tls-skip-verify
[`tls_server_name`]: /reference/#tls-server-name
[`allowed_users`]: /reference/#allowed-users
[`allowed_groups`]: /reference/#allowed-groups
[`allowed_domains`]: /reference/#allowed-domains
[`allowed_idp_claims`]: /reference/#allowed-idp-claims
[`policy`]: /reference/#policy
[`health_checks`]: /reference/#health-checks
[`outlier_detection`]: /reference/#outlier-detection
[`lb_config`]: /reference/#lb-config
[`tls_custom_ca_secret`]: /reference/#tls-custom-ca-secret
[`tls_client_secret`]: /reference/#tls-client-secret
[`tls_downstream_client_ca_secret`]: /reference/#tls-downstream-client-ca-secret
[`secure_upstream`]: /reference/#secure-upstream
[`tls_custom_ca_secret`]: /reference/#tls-custom-certificate-authority
[`tls_client_secret`]: /reference/#tls-client-certificate