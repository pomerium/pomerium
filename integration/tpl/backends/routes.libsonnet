local Routes(mode, idp, dns_suffix) =
  [
    {
      from: 'https://mock-idp.localhost.pomerium.io',
      to: 'http://mock-idp' + dns_suffix + ':8024',
      allow_public_unauthenticated_access: true,
      preserve_host_header: true,
    },
    {
      from: 'https://envoy.localhost.pomerium.io',
      to: 'http://localhost:9901',
      allow_public_unauthenticated_access: true,
    },
    {
      from: 'https://verify.localhost.pomerium.io',
      to: 'http://verify' + dns_suffix + ':80',
      allow_any_authenticated_user: true,
      pass_identity_headers: true,
    },
    {
      from: 'https://websocket-echo.localhost.pomerium.io',
      to: 'http://websocket-echo' + dns_suffix + ':80',
      allow_public_unauthenticated_access: true,
      allow_websockets: true,
    },
    {
      from: 'https://fortio-ui.localhost.pomerium.io',
      to: 'https://fortio' + dns_suffix + ':8080',
      allow_any_authenticated_user: true,
    },
    {
      from: 'https://fortio-ping.localhost.pomerium.io',
      to: 'https://fortio' + dns_suffix + ':8079',
      allow_public_unauthenticated_access: true,
      tls_custom_ca: std.base64(importstr '../files/ca.pem'),
      tls_server_name: 'fortio-ping.localhost.pomerium.io',
    },
    // specify https upstream by IP address
    {
      from: 'https://httpdetails-ip-address.localhost.pomerium.io',
      to: 'https://172.20.0.50:8443',
      allow_public_unauthenticated_access: true,
    },
    // tls_skip_verify
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'https://trusted-httpdetails' + dns_suffix + ':8443',
      path: '/tls-skip-verify-enabled',
      tls_skip_verify: true,
      allow_public_unauthenticated_access: true,
    },
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'https://trusted-httpdetails' + dns_suffix + ':8443',
      path: '/tls-skip-verify-disabled',
      tls_skip_verify: false,
      allow_public_unauthenticated_access: true,
    },
    // tls_server_name
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'https://wrongly-named-httpdetails' + dns_suffix + ':8443',
      path: '/tls-server-name-enabled',
      tls_server_name: 'httpdetails.localhost.notpomerium.io',
      allow_public_unauthenticated_access: true,
    },
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'https://wrongly-named-httpdetails' + dns_suffix + ':8443',
      path: '/tls-server-name-disabled',
      allow_public_unauthenticated_access: true,
    },
    // tls_custom_certificate_authority
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'https://untrusted-httpdetails' + dns_suffix + ':8443',
      path: '/tls-custom-ca-enabled',
      tls_custom_ca: std.base64(importstr '../files/untrusted-ca.pem'),
      tls_server_name: 'httpdetails.localhost.pomerium.io',
      allow_public_unauthenticated_access: true,
    },
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'https://untrusted-httpdetails' + dns_suffix + ':8443',
      path: '/tls-custom-ca-disabled',
      allow_public_unauthenticated_access: true,
    },
    // tls_client_cert
    // {
    //   from: 'http://httpdetails.localhost.pomerium.io',
    //   to: 'https://mtls-http-details' + dns_suffix + ':8443',
    //   path: '/tls-client-cert-enabled',
    //   tls_client_cert: std.base64(tls.trusted.client.cert),
    //   tls_client_key: std.base64(tls.trusted.client.key),
    //   tls_server_name: 'httpdetails.localhost.pomerium.io',
    //   allow_public_unauthenticated_access: true,
    // },
    // {
    //   from: 'http://httpdetails.localhost.pomerium.io',
    //   to: 'https://mtls-http-details' + dns_suffix + ':8443',
    //   path: '/tls-client-cert-disabled',
    //   allow_public_unauthenticated_access: true,
    // },
    // downstream mTLS
    {
      from: 'https://client-cert-required.localhost.pomerium.io',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      tls_downstream_client_ca: std.base64(importstr '../files/downstream-ca-1.pem'),
      allow_any_authenticated_user: true,
    },
    // overlapping downstream mTLS
    {
      from: 'https://client-cert-overlap.localhost.pomerium.io',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      path: '/ca1',
      tls_downstream_client_ca: std.base64(importstr '../files/downstream-ca-1.pem'),
      allow_any_authenticated_user: true,
    },
    {
      from: 'https://client-cert-overlap.localhost.pomerium.io',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      path: '/ca2',
      tls_downstream_client_ca: std.base64(importstr '../files/downstream-ca-2.pem'),
      allow_any_authenticated_user: true,
    },
    // cors_allow_preflight option
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      prefix: '/cors-enabled',
      cors_allow_preflight: true,
    },
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      prefix: '/cors-disabled',
      cors_allow_preflight: false,
    },
    // preserve_host_header option
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      prefix: '/preserve-host-header-enabled',
      allow_public_unauthenticated_access: true,
      preserve_host_header: true,
    },
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      prefix: '/preserve-host-header-disabled',
      allow_public_unauthenticated_access: true,
      preserve_host_header: false,
    },
    // authorization policy
    {
      from: 'https://restricted-httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      allow_any_authenticated_user: true,
      pass_identity_headers: true,
    },
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      prefix: '/by-domain',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      allowed_domains: ['dogs.test'],
      pass_identity_headers: true,
    },
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      prefix: '/by-user',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      allowed_users: ['user1@dogs.test'],
      pass_identity_headers: true,
    },
    // round robin load balancer
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: [
        'http://trusted-1-httpdetails' + dns_suffix + ':8080',
        'http://trusted-2-httpdetails' + dns_suffix + ':8080',
        'http://trusted-3-httpdetails' + dns_suffix + ':8080',
      ],
      prefix: '/round-robin',
      allow_any_authenticated_user: true,
      load_balancing_policy: 'ROUND_ROBIN',
    },
    // ring hash load balancer
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: [
        'http://trusted-1-httpdetails' + dns_suffix + ':8080',
        'http://trusted-2-httpdetails' + dns_suffix + ':8080',
        'http://trusted-3-httpdetails' + dns_suffix + ':8080',
      ],
      prefix: '/ring-hash',
      allow_any_authenticated_user: true,
      load_balancing_policy: 'RING_HASH',
    },
    // maglev load balancer
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: [
        'http://trusted-1-httpdetails' + dns_suffix + ':8080',
        'http://trusted-2-httpdetails' + dns_suffix + ':8080',
        'http://trusted-3-httpdetails' + dns_suffix + ':8080',
      ],
      prefix: '/maglev',
      allow_any_authenticated_user: true,
      load_balancing_policy: 'MAGLEV',
    },
    // catch-all
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      allow_public_unauthenticated_access: true,
      pass_identity_headers: true,
      set_request_headers: {
        'X-Custom-Request-Header': 'custom-request-header-value',
      },
    },
    // websockets
    {
      from: 'https://enabled-ws-echo.localhost.pomerium.io',
      to: 'http://websocket-echo' + dns_suffix + ':80',
      allow_public_unauthenticated_access: true,
      allow_websockets: true,
    },
    {
      from: 'https://disabled-ws-echo.localhost.pomerium.io',
      to: 'http://websocket-echo' + dns_suffix + ':80',
      allow_public_unauthenticated_access: true,
    },
    // cloudrun
    {
      from: 'https://cloudrun.localhost.pomerium.io',
      to: 'http://trusted-httpdetails' + dns_suffix + ':8080',
      allow_public_unauthenticated_access: true,
      pass_identity_headers: true,
      enable_google_cloud_serverless_authentication: true,
      set_request_headers: {
        'x-idp': idp,
      },
    },
  ] + if mode == 'multi' then [
    {
      from: 'https://authenticate.localhost.pomerium.io',
      to: 'https://pomerium-authenticate',
      allow_public_unauthenticated_access: true,
      tls_skip_verify: true,
    },
  ] else [];

{
  Routes: Routes,
}
