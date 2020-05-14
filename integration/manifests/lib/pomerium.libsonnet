local tls = import './tls.libsonnet';

local PomeriumPolicy = function() std.flattenArrays(
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
      allow_public_unauthenticated_access: true,
    },
    {
      from: 'http://restricted-' + domain + '.localhost.pomerium.io',
      to: 'http://' + domain + '.default.svc.cluster.local',
    },
  ]
);

local PomeriumPolicyHash = std.base64(std.md5(std.manifestJsonEx(PomeriumPolicy(), '')));

local PomeriumTLSSecret = function(name) {
  apiVersion: 'v1',
  kind: 'Secret',
  type: 'kubernetes.io/tls',
  metadata: {
    namespace: 'default',
    name: 'pomerium-' + name + '-tls',
  },
  data: {
    'tls-ca.crt': std.base64(tls[name].ca),
    'tls.crt': std.base64(tls[name].cert),
    'tls.key': std.base64(tls[name].key),
    'tls-client.crt': std.base64(tls[name].client.cert),
    'tls-client.key': std.base64(tls[name].client.key),
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

    CERTIFICATE: std.base64(tls.trusted.cert),
    CERTIFICATE_KEY: std.base64(tls.trusted.key),

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
            'authenticate.localhost.pomerium.io',
          ],
        }],
        initContainers: [
          {
            name: 'init',
            image: 'buildpack-deps:buster-curl',
            imagePullPolicy: 'IfNotPresent',
            command: ['sh', '-c', |||
              cp /incoming-certs/trusted/tls-ca.crt /usr/local/share/ca-certificates/pomerium-trusted.crt
              cp /incoming-certs/wrongly-named/tls-ca.crt /usr/local/share/ca-certificates/pomerium-wrongly-named.crt
              update-ca-certificates
            |||],
            volumeMounts: [
              {
                name: 'trusted-incoming-certs',
                mountPath: '/incoming-certs/trusted',
              },
              {
                name: 'wrongly-named-incoming-certs',
                mountPath: '/incoming-certs/wrongly-named',
              },
              {
                name: 'outgoing-certs',
                mountPath: '/etc/ssl/certs',
              },
            ],
          },
        ] + if svc == 'authenticate' then [
          {
            name: 'wait-for-openid',
            image: 'buildpack-deps:buster-curl',
            imagePullPolicy: 'IfNotPresent',
            command: ['sh', '-c', |||
              while ! curl http://openid.default.svc.cluster.local/.well-known/openid-configuration ; do
                sleep 5
              done
            |||],
          },
        ] else [],
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
            name: 'trusted-incoming-certs',
            secret: {
              secretName: 'pomerium-trusted-tls',
            },
          },
          {
            name: 'wrongly-named-incoming-certs',
            secret: {
              secretName: 'pomerium-wrongly-named-tls',
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

local PomeriumNodePortServce = function() {
  apiVersion: 'v1',
  kind: 'Service',
  metadata: {
    namespace: 'default',
    name: 'pomerium-proxy-nodeport',
    labels: {
      app: 'pomerium-proxy',
      'app.kubernetes.io/part-of': 'pomerium',
    },
  },
  spec: {
    type: 'NodePort',
    ports: [
      { name: 'https', port: 443, protocol: 'TCP', targetPort: 'https', nodePort: 31443 },
    ],
    selector: {
      app: 'pomerium-proxy',
    },
  },
};

local PomeriumIngress = function() {
  local proxyHosts = [
    'forward-authenticate.localhost.pomerium.io',
    'httpecho.localhost.pomerium.io',
    'httpdetails.localhost.pomerium.io',
    'restricted-httpdetails.localhost.pomerium.io',
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
        secretName: 'pomerium-trusted-tls',
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
        secretName: 'pomerium-trusted-tls',
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
    PomeriumTLSSecret('trusted'),
    PomeriumTLSSecret('untrusted'),
    PomeriumTLSSecret('wrongly-named'),
    PomeriumService('authenticate'),
    PomeriumDeployment('authenticate'),
    PomeriumService('authorize'),
    PomeriumDeployment('authorize'),
    PomeriumService('cache'),
    PomeriumDeployment('cache'),
    PomeriumService('proxy'),
    PomeriumDeployment('proxy'),
    PomeriumNodePortServce(),
    PomeriumIngress(),
    PomeriumForwardAuthIngress(),
  ],
}
