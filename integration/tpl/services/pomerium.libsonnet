function(idp_provider) {
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
  ],

  services: {
    pomerium: {
      image: 'pomerium/pomerium:${POMERIUM_TAG:-master}',
      environment: {
        AUTHENTICATE_SERVICE_URL: 'https://authenticate.localhost.pomerium.io',
        CERTIFICATE: std.base64(importstr '../files/_wildcard.localhost.pomerium.io.pem'),
        CERTIFICATE_KEY: std.base64(importstr '../files/_wildcard.localhost.pomerium.io-key.pem'),
        CERTIFICATE_AUTHORITY: std.base64(importstr '../files/rootCA.pem'),
        COOKIE_SECRET: 'UYgnt8bxxK5G2sFaNzyqi5Z+OgF8m2akNc0xdQx718w=',
        IDP_PROVIDER: idp_provider,
        IDP_PROVIDER_URL: 'https://mock-idp.localhost.pomerium.io/',
        IDP_CLIENT_ID: 'CLIENT_ID',
        IDP_CLIENT_SECRET: 'CLIENT_SECRET',
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
