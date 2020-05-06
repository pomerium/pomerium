local tls = import './tls.libsonnet';

local PomeriumPolicy = function() std.flattenArrays([
  [
    {
      from: 'http://' + domain + '.localhost.pomerium.io',
      prefix: '/by-domain',
      to: 'http://' + domain + '.default.svc.cluster.local',
      allowed_domains: ['dogs.test'],
    },
    {
      from: 'http://' + domain + '.localhost.pomerium.io',
      prefix: '/by-user',
      to: 'http://' + domain + '.default.svc.cluster.local',
      allowed_users: ['bob@dogs.test'],
    },
    {
      from: 'http://' + domain + '.localhost.pomerium.io',
      prefix: '/by-group',
      to: 'http://' + domain + '.default.svc.cluster.local',
      allowed_groups: ['admin'],
    },
    {
      from: 'http://' + domain + '.localhost.pomerium.io',
      to: 'http://' + domain + '.default.svc.cluster.local',
      prefix: '/cors-enabled',
      cors_allow_preflight: true,
    },
    {
      from: 'http://' + domain + '.localhost.pomerium.io',
      to: 'http://' + domain + '.default.svc.cluster.local',
      prefix: '/cors-disabled',
      cors_allow_preflight: false,
    },
    {
      from: 'http://' + domain + '.localhost.pomerium.io',
      to: 'http://' + domain + '.default.svc.cluster.local',
      allow_public_unauthenticated_access: true,
    },
  ]
  for domain in ['httpdetails', 'fa-httpdetails', 'ws-echo']
]) + [
  {
    from: 'http://enabled-ws-echo.localhost.pomerium.io',
    to: 'http://ws-echo.default.svc.cluster.local',
    allow_public_unauthenticated_access: true,
    allow_websockets: true,
  },
  {
    from: 'http://disabled-ws-echo.localhost.pomerium.io',
    to: 'http://ws-echo.default.svc.cluster.local',
    allow_public_unauthenticated_access: true,
  },
];

local PomeriumPolicyHash = std.base64(std.md5(std.manifestJsonEx(PomeriumPolicy(), '')));

local PomeriumTLSSecret = function() {
  apiVersion: 'v1',
  kind: 'Secret',
  type: 'kubernetes.io/tls',
  metadata: {
    namespace: 'default',
    name: 'pomerium-tls',
  },
  data: {
    'tls.crt': std.base64(tls.cert),
    'tls.key': std.base64(tls.key),
  },
};

local PomeriumCAsConfigMap = function() {
  apiVersion: 'v1',
  kind: 'ConfigMap',
  metadata: {
    namespace: 'default',
    name: 'pomerium-cas',
    labels: {
      'app.kubernetes.io/part-of': 'pomerium',
    },
  },
  data: {
    'pomerium.crt': tls.ca,
  },
};

local PomeriumConfigMap = function() {
  apiVersion: 'v1',
  kind: 'ConfigMap',
  metadata: {
    namespace: 'default',
    name: 'pomerium',
    labels: {
      'app.kubernetes.io/part-of': 'pomerium',
    },
  },
  data: {
    ADDRESS: ':443',
    GRPC_ADDRESS: ':5080',
    GRPC_INSECURE: 'true',
    DEBUG: 'true',
    LOG_LEVEL: 'debug',

    AUTHENTICATE_SERVICE_URL: 'https://authenticate.localhost.pomerium.io',
    AUTHENTICATE_CALLBACK_PATH: '/oauth2/callback',
    AUTHORIZE_SERVICE_URL: 'http://authorize.default.svc.cluster.local:5080',
    CACHE_SERVICE_URL: 'http://cache.default.svc.cluster.local:5080',
    FORWARD_AUTH_URL: 'https://forward-authenticate.localhost.pomerium.io',

    SHARED_SECRET: 'Wy+c0uSuIM0yGGXs82MBwTZwRiZ7Ki2T0LANnmzUtkI=',
    COOKIE_SECRET: 'eZ91a/j9fhgki9zPDU5zHdQWX4io89pJanChMVa5OoM=',

    CERTIFICATE: std.base64(tls.cert),
    CERTIFICATE_KEY: std.base64(tls.key),

    IDP_PROVIDER: 'oidc',
    IDP_PROVIDER_URL: 'https://openid.localhost.pomerium.io',
    IDP_CLIENT_ID: 'pomerium-authenticate',
    IDP_CLIENT_SECRET: 'pomerium-authenticate-secret',

    POLICY: std.base64(std.manifestYamlDoc(PomeriumPolicy())),
  },
};

local PomeriumDeployment = function(svc) {
  apiVersion: 'apps/v1',
  kind: 'Deployment',
  metadata: {
    namespace: 'default',
    name: 'pomerium-' + svc,
    labels: {
      app: 'pomerium-' + svc,
      'app.kubernetes.io/part-of': 'pomerium',
    },
  },
  spec: {
    replicas: 1,
    selector: {
      matchLabels: {
        app: 'pomerium-' + svc,
      },
    },
    template: {
      metadata: {
        labels: {
          app: 'pomerium-' + svc,
          'app.kubernetes.io/part-of': 'pomerium',
        },
        annotations: {
          'policy-version': PomeriumPolicyHash,
        },
      },
      spec: {
        hostAliases: [{
          ip: '10.96.1.1',
          hostnames: [
            'openid.localhost.pomerium.io',
          ],
        }],
        initContainers: [{
          name: 'pomerium-' + svc + '-certs',
          image: 'buildpack-deps:buster-curl',
          imagePullPolicy: 'Always',
          command: ['sh', '-c', |||
            cp /incoming-certs/* /usr/local/share/ca-certificates
            update-ca-certificates
          |||],
          volumeMounts: [
            {
              name: 'incoming-certs',
              mountPath: '/incoming-certs',
            },
            {
              name: 'outgoing-certs',
              mountPath: '/etc/ssl/certs',
            },
          ],
        }],
        containers: [{
          name: 'pomerium-' + svc,
          image: 'pomerium/pomerium:dev',
          imagePullPolicy: 'IfNotPresent',
          envFrom: [{
            configMapRef: { name: 'pomerium' },
          }],
          env: [{
            name: 'SERVICES',
            value: svc,
          }],
          ports: [
            { name: 'https', containerPort: 443 },
            { name: 'grpc', containerPort: 5080 },
          ],
          volumeMounts: [
            {
              name: 'outgoing-certs',
              mountPath: '/etc/ssl/certs',
            },
          ],
        }],
        volumes: [
          {
            name: 'incoming-certs',
            configMap: {
              name: 'pomerium-cas',
            },
          },
          {
            name: 'outgoing-certs',
            emptyDir: {},
          },
        ],
      },
    },
  },
};

local PomeriumService = function(svc) {
  apiVersion: 'v1',
  kind: 'Service',
  metadata: {
    namespace: 'default',
    name: svc,
    labels: {
      app: 'pomerium-' + svc,
      'app.kubernetes.io/part-of': 'pomerium',
    },
  },
  spec: {
    ports: [
      {
        name: 'https',
        port: 443,
        targetPort: 'https',
      },
      {
        name: 'grpc',
        port: 5080,
        targetPort: 'grpc',
      },
    ],
    selector: {
      app: 'pomerium-' + svc,
    },
  },
};

local PomeriumIngress = function() {
  local proxyHosts = [
    'forward-authenticate.localhost.pomerium.io',
    'httpecho.localhost.pomerium.io',
    'httpdetails.localhost.pomerium.io',
    'enabled-ws-echo.localhost.pomerium.io',
    'disabled-ws-echo.localhost.pomerium.io',
  ],

  apiVersion: 'extensions/v1beta1',
  kind: 'Ingress',
  metadata: {
    namespace: 'default',
    name: 'pomerium',
    annotations: {
      'kubernetes.io/ingress.class': 'nginx',
      'nginx.ingress.kubernetes.io/backend-protocol': 'HTTPS',
      'nginx.ingress.kubernetes.io/proxy-buffer-size': '16k',
    },
  },
  spec: {
    tls: [
      {
        hosts: [
          'authenticate.localhost.pomerium.io',
        ] + proxyHosts,
        secretName: 'pomerium-tls',
      },
    ],
    rules: [
      {
        host: 'authenticate.localhost.pomerium.io',
        http: {
          paths: [
            {
              path: '/',
              backend: {
                serviceName: 'authenticate',
                servicePort: 'https',
              },
            },
          ],
        },
      },
    ] + [{
      host: host,
      http: {
        paths: [{
          path: '/',
          backend: {
            serviceName: 'proxy',
            servicePort: 'https',
          },
        }],
      },
    } for host in proxyHosts],
  },
};

local PomeriumForwardAuthIngress = function() {
  apiVersion: 'extensions/v1beta1',
  kind: 'Ingress',
  metadata: {
    namespace: 'default',
    name: 'pomerium-fa',
    annotations: {
      'kubernetes.io/ingress.class': 'nginx',
      'nginx.ingress.kubernetes.io/auth-url': 'https://forward-authenticate.localhost.pomerium.io/verify?uri=$scheme://$host$request_uri',
      'nginx.ingress.kubernetes.io/auth-signin': 'https://forward-authenticate.localhost.pomerium.io/?uri=$scheme://$host$request_uri',
      'nginx.ingress.kubernetes.io/proxy-buffer-size': '16k',
    },
  },
  spec: {
    tls: [
      {
        hosts: [
          'fa-httpdetails.localhost.pomerium.io',
        ],
        secretName: 'pomerium-tls',
      },
    ],
    rules: [
      {
        host: 'fa-httpdetails.localhost.pomerium.io',
        http: {
          paths: [
            {
              path: '/.pomerium/',
              backend: {
                serviceName: 'proxy',
                servicePort: 'https',
              },
            },
            {
              path: '/',
              backend: {
                serviceName: 'httpdetails',
                servicePort: 'http',
              },
            },
          ],
        },
      },
    ],
  },
};

{
  apiVersion: 'v1',
  kind: 'List',
  items: [
    PomeriumConfigMap(),
    PomeriumCAsConfigMap(),
    PomeriumTLSSecret(),
    PomeriumService('authenticate'),
    PomeriumDeployment('authenticate'),
    PomeriumService('authorize'),
    PomeriumDeployment('authorize'),
    PomeriumService('cache'),
    PomeriumDeployment('cache'),
    PomeriumService('proxy'),
    PomeriumDeployment('proxy'),
    PomeriumIngress(),
    PomeriumForwardAuthIngress(),
  ],
}
