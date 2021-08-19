local Routes = (import './routes.libsonnet').Routes;

local GoogleCloudServerlessAuthenticationServiceAccount() =
  {
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
        { name: 'grpc', port: 5443, targetPort: 'grpc', nodePort: 5443 },
      ],
    },
  };


local Environment(mode, idp, dns_suffix) =
  {
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
    JWT_CLAIMS_HEADERS: 'email,groups,user',
    LOG_LEVEL: 'info',
    POLICY: std.base64(std.manifestJsonEx(Routes(mode, idp, dns_suffix), '')),
    SHARED_SECRET: 'UYgnt8bxxK5G2sFaNzyqi5Z+OgF8m2akNc0xdQx718w=',
    SIGNING_KEY: std.base64(importstr '../files/signing-key.pem'),
    SIGNING_KEY_ALGORITHM: 'ES256',
  } + if mode == 'multi' then {
    AUTHORIZE_SERVICE_URL: 'https://pomerium-authorize:5443',
    DATABROKER_SERVICE_URL: 'https://pomerium-databroker:5443',
    GRPC_ADDRESS: ':5443',
    GRPC_INSECURE: 'false',
    OVERRIDE_CERTIFICATE_NAME: '*.localhost.pomerium.io',
  } else if mode == 'traefik' then {
    FORWARD_AUTH_URL: 'https://forward-authenticate.localhost.pomerium.io',
  } else {};

function(mode, idp, dns_suffix='') {
  local name = 'pomerium',
  local image = 'pomerium/pomerium:${POMERIUM_TAG:-master}',
  local environment = Environment(mode, idp, dns_suffix),

  compose: {
    services: if mode == 'multi' then {
      [name + '-authorize']: {
        image: image,
        environment: environment {
          SERVICES: 'authorize',
        },
        ports: [
          '9904:9901/tcp',
          '5446:5443/tcp',
        ],
        links: [
          'pomerium-proxy:mock-idp.localhost.pomerium.io',
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
        links: [
          'pomerium-proxy:mock-idp.localhost.pomerium.io',
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
    } else if mode == 'traefik' then {
      [name]: {
        image: image,
        environment: environment,
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
