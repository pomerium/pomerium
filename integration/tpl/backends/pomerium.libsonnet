function(idp) {
  local routes = [
    {
      from: 'https://mock-idp.localhost.pomerium.io',
      to: 'http://mock-idp:8024',
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
      to: 'http://verify:80',
      allow_any_authenticated_user: true,
      pass_identity_headers: true,
    },
    {
      from: 'https://websocket-echo.localhost.pomerium.io',
      to: 'http://websocket-echo:80',
      allow_public_unauthenticated_access: true,
      allow_websockets: true,
    },
    {
      from: 'https://fortio-ui.localhost.pomerium.io',
      to: 'https://fortio:8080',
      allow_any_authenticated_user: true,
    },
    {
      from: 'https://fortio-ping.localhost.pomerium.io',
      to: 'https://fortio:8079',
      allow_public_unauthenticated_access: true,
      tls_custom_ca: std.base64(importstr '../files/ca.pem'),
      tls_server_name: 'fortio-ping.localhost.pomerium.io',
    },
    {
      from: 'tcp+https://redis.localhost.pomerium.io:6379',
      to: 'tcp://redis:6379',
      allow_any_authenticated_user: true,
    },
    // tls_skip_verify
    {
      from: 'http://httpdetails.localhost.pomerium.io',
      to: 'https://trusted-httpdetails:8443',
      path: '/tls-skip-verify-enabled',
      tls_skip_verify: true,
      allow_public_unauthenticated_access: true,
    },
    {
      from: 'http://httpdetails.localhost.pomerium.io',
      to: 'https://trusted-httpdetails:8443',
      path: '/tls-skip-verify-disabled',
      tls_skip_verify: false,
      allow_public_unauthenticated_access: true,
    },
    // tls_server_name
    {
      from: 'http://httpdetails.localhost.pomerium.io',
      to: 'https://wrongly-named-httpdetails:8443',
      path: '/tls-server-name-enabled',
      tls_server_name: 'httpdetails.localhost.notpomerium.io',
      allow_public_unauthenticated_access: true,
    },
    {
      from: 'http://httpdetails.localhost.pomerium.io',
      to: 'https://wrongly-named-httpdetails:8443',
      path: '/tls-server-name-disabled',
      allow_public_unauthenticated_access: true,
    },
    // tls_custom_certificate_authority
    {
      from: 'http://httpdetails.localhost.pomerium.io',
      to: 'https://untrusted-httpdetails:8443',
      path: '/tls-custom-ca-enabled',
      tls_custom_ca: std.base64(importstr '../files/untrusted-ca.pem'),
      tls_server_name: 'httpdetails.localhost.pomerium.io',
      allow_public_unauthenticated_access: true,
    },
    {
      from: 'http://httpdetails.localhost.pomerium.io',
      to: 'https://untrusted-httpdetails:8443',
      path: '/tls-custom-ca-disabled',
      allow_public_unauthenticated_access: true,
    },
    // tls_client_cert
    // {
    //   from: 'http://httpdetails.localhost.pomerium.io',
    //   to: 'https://mtls-http-details:8443',
    //   path: '/tls-client-cert-enabled',
    //   tls_client_cert: std.base64(tls.trusted.client.cert),
    //   tls_client_key: std.base64(tls.trusted.client.key),
    //   tls_server_name: 'httpdetails.localhost.pomerium.io',
    //   allow_public_unauthenticated_access: true,
    // },
    // {
    //   from: 'http://httpdetails.localhost.pomerium.io',
    //   to: 'https://mtls-http-details:8443',
    //   path: '/tls-client-cert-disabled',
    //   allow_public_unauthenticated_access: true,
    // },
    // cors_allow_preflight option
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails:8080',
      prefix: '/cors-enabled',
      cors_allow_preflight: true,
    },
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails:8080',
      prefix: '/cors-disabled',
      cors_allow_preflight: false,
    },
    // preserve_host_header option
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails:8080',
      prefix: '/preserve-host-header-enabled',
      allow_public_unauthenticated_access: true,
      preserve_host_header: true,
    },
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails:8080',
      prefix: '/preserve-host-header-disabled',
      allow_public_unauthenticated_access: true,
      preserve_host_header: false,
    },
    {
      from: 'https://httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails:8080',
      allow_public_unauthenticated_access: true,
      pass_identity_headers: true,
      set_request_headers: {
        'X-Custom-Request-Header': 'custom-request-header-value',
      },
    },
    {
      from: 'https://restricted-httpdetails.localhost.pomerium.io',
      to: 'http://trusted-httpdetails:8080',
      allow_any_authenticated_user: true,
      pass_identity_headers: true,
    },
    // websockets
    {
      from: 'https://enabled-ws-echo.localhost.pomerium.io',
      to: 'http://websocket-echo:80',
      allow_public_unauthenticated_access: true,
      allow_websockets: true,
    },
    {
      from: 'https://disabled-ws-echo.localhost.pomerium.io',
      to: 'http://websocket-echo:80',
      allow_public_unauthenticated_access: true,
    },
  ],

  services: {
    pomerium: {
      image: 'pomerium/pomerium:${POMERIUM_TAG:-master}',
      environment: {
        AUTHENTICATE_SERVICE_URL: 'https://authenticate.localhost.pomerium.io',
        CERTIFICATE: std.base64(importstr '../files/trusted.pem'),
        CERTIFICATE_KEY: std.base64(importstr '../files/trusted-key.pem'),
        CERTIFICATE_AUTHORITY: std.base64(importstr '../files/ca.pem'),
        COOKIE_SECRET: 'UYgnt8bxxK5G2sFaNzyqi5Z+OgF8m2akNc0xdQx718w=',
        DATABROKER_STORAGE_TYPE: 'redis',
        DATABROKER_STORAGE_CONNECTION_STRING: 'redis://redis:6379',
        IDP_PROVIDER: idp,
        IDP_PROVIDER_URL: 'https://mock-idp.localhost.pomerium.io/',
        IDP_CLIENT_ID: 'CLIENT_ID',
        IDP_CLIENT_SECRET: 'CLIENT_SECRET',
        LOG_LEVEL: 'info',
        POLICY: std.base64(std.manifestJsonEx(routes, '')),
        SHARED_SECRET: 'UYgnt8bxxK5G2sFaNzyqi5Z+OgF8m2akNc0xdQx718w=',
        SIGNING_KEY: std.base64(importstr '../files/signing-key.pem'),
        SIGNING_KEY_ALGORITHM: 'ES256',
      },
      ports: [
        '443:443/tcp',
        '80:80/tcp',
      ],
    },
  },
  volumes: {},
}
