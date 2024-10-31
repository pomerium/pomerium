local utils = import '../utils.libsonnet';
local Routes = (import './routes.libsonnet').Routes;

local GoogleCloudServerlessAuthenticationServiceAccount(dns_suffix='') =
  {
    type: 'service_account',
    project_id: 'pomerium-redacted',
    private_key_id: 'e07f7c93870c7e03f883560ecd8fd0f4d27b0081',
    private_key: importstr '../files/trusted-key.pem',
    client_email: 'redacted@pomerium-redacted.iam.gserviceaccount.com',
    client_id: '101215990458000334387',
    auth_uri: 'http://mock-idp' + dns_suffix + ':8024',
    token_uri: 'http://mock-idp' + dns_suffix + ':8024/token',
    auth_provider_x509_cert_url: 'http://mock-idp' + dns_suffix + ':8024',
    client_x509_cert_url: 'http://mock-idp' + dns_suffix + ':8024',
  };

local KubernetesDeployment(name, image, environment) =
  {
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
              { name: 'quic', containerPort: 443, protocol: 'UDP' },
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

local KubernetesService(name) =
  {
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
        { name: 'quic', port: 443, targetPort: 'quic', nodePort: 443, protocol: 'UDP' },
        { name: 'grpc', port: 5443, targetPort: 'grpc', nodePort: 5443 },
      ],
    },
  };


local Environment(mode, idp, authentication_flow, dns_suffix) =
  {
    AUTHENTICATE_SERVICE_URL: 'https://authenticate.localhost.pomerium.io',
    CERTIFICATE: std.base64(importstr '../files/trusted.pem'),
    CERTIFICATE_KEY: std.base64(importstr '../files/trusted-key.pem'),
    CERTIFICATE_AUTHORITY: std.base64(importstr '../files/ca.pem'),
    CODEC_TYPE: 'http3',
    COOKIE_SECRET: 'UYgnt8bxxK5G2sFaNzyqi5Z+OgF8m2akNc0xdQx718w=',
    DATABROKER_STORAGE_TYPE: 'postgres',
    DATABROKER_STORAGE_CONNECTION_STRING: 'postgres://pomerium:password@postgres:5432/test',
    DOWNSTREAM_MTLS_CRL: std.base64(importstr '../files/downstream-crl.pem'),
    ENVOY_ADMIN_ADDRESS: '0.0.0.0:9901',
    GOOGLE_CLOUD_SERVERLESS_AUTHENTICATION_SERVICE_ACCOUNT: std.base64(std.manifestJsonEx(
      GoogleCloudServerlessAuthenticationServiceAccount(dns_suffix), ''
    )),
    IDP_PROVIDER: idp,
    IDP_PROVIDER_URL: 'https://mock-idp.localhost.pomerium.io/',
    IDP_CLIENT_ID: 'CLIENT_ID',
    IDP_CLIENT_SECRET: 'CLIENT_SECRET',
    JWT_CLAIMS_HEADERS: 'email,groups,user',
    LOG_LEVEL: 'info',
    POLICY: std.base64(std.manifestJsonEx(Routes(mode, idp, dns_suffix), '')),
    RUNTIME_FLAGS: '{"pomerium_jwt_endpoint": true}',
    SHARED_SECRET: 'UYgnt8bxxK5G2sFaNzyqi5Z+OgF8m2akNc0xdQx718w=',
    SIGNING_KEY: std.base64(importstr '../files/signing-key.pem'),
    SIGNING_KEY_ALGORITHM: 'ES256',
  } + (
    if mode == 'multi' then {
      AUTHENTICATE_INTERNAL_SERVICE_URL: 'https://pomerium-authenticate',
      AUTHORIZE_SERVICE_URL: 'https://pomerium-authorize:5443',
      DATABROKER_SERVICE_URL: 'https://pomerium-databroker:5443',
      GRPC_ADDRESS: ':5443',
      GRPC_INSECURE: 'false',
    } else {}
  ) + (
    if authentication_flow == 'stateless' then {
      DEBUG_FORCE_AUTHENTICATE_FLOW: 'stateless',
    } else {}
  );

local ComposeService(name, definition, additionalAliases=[]) =
  utils.ComposeService(name, definition {
    depends_on: {
      [name + '-ready']: {
        condition: 'service_completed_successfully',
      }
      for name in [
        'fortio',
        'mock-idp',
        'postgres',
        'trusted-httpdetails',
        'trusted-1-httpdetails',
        'trusted-2-httpdetails',
        'trusted-3-httpdetails',
        'untrusted-httpdetails',
        'verify',
        'websocket-echo',
        'wrongly-named-httpdetails',
      ]
    },
  }, additionalAliases);

function(mode, idp, authentication_flow, dns_suffix='') {
  local name = 'pomerium',
  local image = 'pomerium/pomerium:${POMERIUM_TAG:-main}',
  local environment = Environment(mode, idp, authentication_flow, dns_suffix),

  compose: {
    services: if mode == 'multi' then
      ComposeService(name + '-authorize', {
        image: image,
        environment: environment {
          SERVICES: 'authorize',
          CERTIFICATE: std.base64(importstr '../files/pomerium-authorize.pem'),
          CERTIFICATE_KEY: std.base64(importstr '../files/pomerium-authorize-key.pem'),
        },
        ports: [
          '9904:9901/tcp',
          '5446:5443/tcp',
        ],
      }) +
      ComposeService(name + '-authenticate', {
        image: image,
        environment: environment {
          SERVICES: 'authenticate',
        },
        ports: [
          '9903:9901/tcp',
          '5445:5443/tcp',
        ],
      }, ['authenticate.localhost.pomerium.io']) +
      ComposeService(name + '-databroker', {
        image: image,
        environment: environment {
          SERVICES: 'databroker',
          CERTIFICATE: std.base64(importstr '../files/pomerium-databroker.pem'),
          CERTIFICATE_KEY: std.base64(importstr '../files/pomerium-databroker-key.pem'),
        },
        ports: [
          '9902:9901/tcp',
          '5444:5443/tcp',
        ],
      }) +
      ComposeService(name + '-proxy', {
        image: image,
        environment: environment {
          SERVICES: 'proxy',
        },
        ports: [
          '80:80/tcp',
          '443:443/tcp',
          '443:443/udp',
          '5443:5443/tcp',
          '9901:9901/tcp',
        ],
      }, ['mock-idp.localhost.pomerium.io'])
    else
      ComposeService(name, {
        image: image,
        environment: environment,
        ports: [
          '80:80/tcp',
          '443:443/tcp',
          '443:443/udp',
          '9901:9901/tcp',
        ],
      }, ['authenticate.localhost.pomerium.io']),
    volumes: {},
  },
  kubernetes: [
    KubernetesService(name),
    KubernetesDeployment(name, image, environment),
  ],
}
