---
title: Ingress Controller
lang: en-US
meta:
  - name: keywords
    content: pomerium identity-access-proxy oidc kubernetes Ingress reverse-proxy
---

# Kubernetes Ingress Controller

Use Pomerium as a first class secure-by-default Ingress Controller. Dynamically provision routes from Ingress resources and set policy based on annotations.

TODO: Funfact: you can dynamically create and remove routes with OSS Pomerium using the Ingress Controller, which you can't do otherwise.

## Installation

## Prerequisites

TODO: Cert manager. This is covered by the [helm] instructions, but to do make one independently...

TODO: REDIS Backend with persistence is highly recommended. 

TODO: CloudRun endpoints can be easily supported using "internal traffic policy", if they are deployed to the same cloud project as Pomerium. 

### Helm
Our instructions for [Installing Pomering Using Helm](/docs/k8s/helm.md) includes the Ingress Controller as part of the documented configuration. The values to adjust based on your configuration usually include:

```yaml
ingressController:
  enabled: true
```
### Docker Image

You may deploy your own manifests by using the `pomerium/ingress-controller` docker image.

### System Requirements

- Kubernetes v0.19.0+
- Pomerium [Helm Chart](https://github.com/pomerium/pomerium-helm/tree/master/charts/pomerium) v25.0.0+

### Limitations

::: warning
Only one Ingress Controller instance/replica is supported per Pomerium cluster.
:::

## Configuration


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

## Usage

### Defining Routes

If you've tested Pomerium using the all-in-one service, you're probably familiar with configuring routes in Pomerium's `config.yaml`. In this environmenzt, each route is defined as a.... what @travis?

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

| Annotation              | Description |
| ----------------------- | ------------------------------------------------------------------------------------------- |
| [`cors_allow_preflight`]                    | [See Reference for details.][`cors_allow_preflight`]
| [`allow_public_unauthenticated_access`]     | [See Reference for details.][`allow_public_unauthenticated_access`]
| [`allow_any_authenticated_user`]            | [See Reference for details.][`allow_any_authenticated_user`]
| [`timeout`]                                 | [See Reference for details.][`timeout`]
| [`idle_timeout`]                            | [See Reference for details.][`idle_timeout`]
| [`allow_websockets`]                        | [See Reference for details.][`allow_websockets`]
| [`set_request_headers`]                     | [See Reference for details.][`set_request_headers`]
| [`remove_request_headers`]                  | [See Reference for details.][`remove_request_headers`]
| [`set_response_headers`]                    | [See Reference for details.][`set_response_headers`]
| [`rewrite_response_headers`]                | [See Reference for details.][`rewrite_response_headers`]
| [`preserve_host_header`]                    | [See Reference for details.][`preserve_host_header`]
| [`pass_identity_headers`]                   | [See Reference for details.][`pass_identity_headers`]
| [`tls_skip_verify`]                         | [See Reference for details.][`tls_skip_verify`]
| [`tls_server_name`]                         | [See Reference for details.][`tls_server_name`]
| [`allowed_users`]                           | [See Reference for details.][`allowed_users`]
| [`allowed_groups`]                          | [See Reference for details.][`allowed_groups`]
| [`allowed_domains`]                         | [See Reference for details.][`allowed_domains`]
| [`allowed_idp_claims`]                      | [See Reference for details.][`allowed_idp_claims`]
| [`policy`]                                  | [See Reference for details.][`policy`]
| [`health_checks`]                           | [See Reference for details.][`health_checks`]
| [`outlier_detection`]                       | [See Reference for details.][`outlier_detection`]
| [`lb_config`]                               | [See Reference for details.][`lb_config`]
| [`tls_custom_ca_secret`]                    | Name of Kubernetes `tls` Secret containing a custom [CA certificate](https://www.pomerium.com/reference/#tls-custom-certificate-authority) for the upstream
| [`tls_client_secret`]                       | Name of Kubernetes `tls` Secret containing a [client certificate](https://www.pomerium.com/reference/#tls-client-certificate) for connecting to the upstream
| [`tls_downstream_client_ca_secret`]         | Name of Kubernetes `tls` Secret containing a [Client CA](https://www.pomerium.com/reference/#tls-downstream-client-certificate-authority) for validating downstream clients
| [`secure_upstream`]                         | When set to true, use `https` when connecting to the upstream endpoint.
	
::: tip
Every value for the annotations above must be in `string` format.
:::

### Cert Manager Integration

TODO: @travisgroth

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

If your domain has HSTS enabled, and you visit i.e. _authenticate_ endpoint while Pomerium is using self-signed bootstrap certificate, 
or i.e. LetsEncrypt staging certificate, before cert-manager provisioned a production certificate, it may get pinned in your browser and need be reset. 

https://www.ssl2buy.com/wiki/how-to-clear-hsts-settings-on-chrome-firefox-and-ie-browsers

## HTTPS endpoints

`Ingress` spec defines that all communications to the service should happen in cleartext. Pomerium supports HTTPS endpoints, including mTLS.

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