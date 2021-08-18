local GoogleCloudServerlessAuthenticationServiceAccount() = {
  type: 'service_account',
  project_id: 'pomerium-redacted',
  private_key_id: 'e07f7c93870c7e03f883560ecd8fd0f4d27b0081',
  private_key: importstr '../files/trusted-key.pem',
  client_email: 'redacted@pomerium-redacted.iam.gserviceaccount.com',
  client_id: '101215990458000334387',
  auth_uri: 'https://mock-idp.localhost.pomerium.io/',
  token_uri: 'https://mock-idp.localhost.pomerium.io/token',
  auth_provider_x509_cert_url: 'https://mock-idp.localhost.pomerium.io/',
  client_x509_cert_url: 'https://mock-idp.localhost.pomerium.io/',
};

local KubernetesDeployment(name, image, environment) = {
  apiVersion: 'apps/v1',
  kind: 'Deployment',
  metadata: {
    namespace: 'default',
    name: name,
  },
  spec: {
    replicas: 1,
    selector: { matchLabels: { app: name } },
    template: {
      metadata: {
        labels: { app: name },
      },
      spec: {
        containers: [{
          name: name,
          image: image,
          imagePullPolicy: 'IfNotPresent',
          ports: [
            { name: 'http', containerPort: 80 },
            { name: 'https', containerPort: 443 },
            { name: 'grpc', containerPort: 5443 },
          ],
          env: [
            {
              name: k,
              value: environment[k],
            }
            for k in std.objectFields(environment)
          ],
        }],
      },
    },
  },
};

local KubernetesService(name) = {
  apiVersion: 'v1',
  kind: 'Service',
  metadata: {
    namespace: 'default',
    name: name,
    labels: { app: name },
  },
  spec: {
    type: 'NodePort',
    selector: { app: name },
    ports: [
      { name: 'http', port: 80, targetPort: 'http', nodePort: 80 },
      { name: 'https', port: 443, targetPort: 'https', nodePort: 443 },
      { name: 'grpc', port: 5443, targetPort: 'grpc', nodePort: 5443 },
    ],
  },
};

local Routes(multi, idp, dns_suffix) = [
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
  {
    from: 'tcp+https://redis.localhost.pomerium.io:6379',
    to: 'tcp://redis' + dns_suffix + ':6379',
    allow_any_authenticated_user: true,
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
] + if multi then [
  {
    from: 'https://authenticate.localhost.pomerium.io',
    to: 'https://pomerium-authenticate',
    allow_public_unauthenticated_access: true,
    host_rewrite: 'authenticate.localhost.pomerium.io',
    tls_skip_verify: true,
  },
] else [];

local Environment(multi, idp, dns_suffix) = {
  AUTHENTICATE_SERVICE_URL: 'https://authenticate.localhost.pomerium.io',
  CERTIFICATE: std.base64(importstr '../files/trusted.pem'),
  CERTIFICATE_KEY: std.base64(importstr '../files/trusted-key.pem'),
  CERTIFICATE_AUTHORITY: std.base64(importstr '../files/ca.pem'),
  COOKIE_SECRET: 'UYgnt8bxxK5G2sFaNzyqi5Z+OgF8m2akNc0xdQx718w=',
  DATABROKER_STORAGE_TYPE: 'redis',
  DATABROKER_STORAGE_CONNECTION_STRING: 'redis://redis:6379',
  ENVOY_ADMIN_ADDRESS: '0.0.0.0:9901',
  GOOGLE_CLOUD_SERVERLESS_AUTHENTICATION_SERVICE_ACCOUNT: std.base64(std.manifestJsonEx(
    GoogleCloudServerlessAuthenticationServiceAccount(), ''
  )),
  IDP_PROVIDER: idp,
  IDP_PROVIDER_URL: 'https://mock-idp.localhost.pomerium.io/',
  IDP_CLIENT_ID: 'CLIENT_ID',
  IDP_CLIENT_SECRET: 'CLIENT_SECRET',
  LOG_LEVEL: 'info',
  POLICY: std.base64(std.manifestJsonEx(Routes(multi, idp, dns_suffix), '')),
  SHARED_SECRET: 'UYgnt8bxxK5G2sFaNzyqi5Z+OgF8m2akNc0xdQx718w=',
  SIGNING_KEY: std.base64(importstr '../files/signing-key.pem'),
  SIGNING_KEY_ALGORITHM: 'ES256',
} + if multi then {
  AUTHORIZE_SERVICE_URL: 'https://pomerium-authorize:5443',
  DATABROKER_SERVICE_URL: 'https://pomerium-databroker:5443',
  GRPC_ADDRESS: ':5443',
  GRPC_INSECURE: 'false',
  OVERRIDE_CERTIFICATE_NAME: '*.localhost.pomerium.io',
} else {};

function(multi, idp, dns_suffix='') {
  local name = 'pomerium',
  local image = 'pomerium/pomerium:${POMERIUM_TAG:-master}',
  local environment = Environment(multi, idp, dns_suffix),

  compose: {
    services: if multi then {
      [name + '-authorize']: {
        image: image,
        environment: environment {
          SERVICES: 'authorize',
        },
        ports: [
          '9904:9901/tcp',
          '5446:5443/tcp',
        ],
      },
      [name + '-authenticate']: {
        image: image,
        environment: environment {
          SERVICES: 'authenticate',
        },
        ports: [
          '9903:9901/tcp',
          '5445:5443/tcp',
        ],
        links: [
          'pomerium-proxy:mock-idp.localhost.pomerium.io',
        ],
      },
      [name + '-databroker']: {
        image: image,
        environment: environment {
          SERVICES: 'databroker',
        },
        ports: [
          '9902:9901/tcp',
          '5444:5443/tcp',
        ],
      },
      [name + '-proxy']: {
        image: image,
        environment: environment {
          SERVICES: 'proxy',
        },
        ports: [
          '80:80/tcp',
          '443:443/tcp',
          '5443:5443/tcp',
          '9901:9901/tcp',
        ],
      },
    } else {
      [name]: {
        image: image,
        environment: environment,
        ports: [
          '80:80/tcp',
          '443:443/tcp',
          '9901:9901/tcp',
        ],
      },
    },
    volumes: {},
  },
  kubernetes: [
    KubernetesService(name),
    KubernetesDeployment(name, image, environment),
  ],
}
