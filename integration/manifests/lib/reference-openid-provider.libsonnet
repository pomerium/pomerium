local Service = function() {
  apiVersion: 'v1',
  kind: 'Service',
  metadata: {
    namespace: 'default',
    name: 'openid',
    labels: {
      app: 'openid',
      'app.kubernetes.io/part-of': 'openid',
    },
  },
  spec: {
    selector: { app: 'openid' },
    ports: [
      {
        name: 'http',
        port: 80,
        targetPort: 'http',
      },
    ],
  },
};

local Deployment = function() {
  apiVersion: 'apps/v1',
  kind: 'Deployment',
  metadata: {
    namespace: 'default',
    name: 'openid',
    labels: {
      app: 'openid',
      'app.kubernetes.io/part-of': 'openid',
    },
  },
  spec: {
    replicas: 1,
    selector: { matchLabels: { app: 'openid' } },
    template: {
      metadata: {
        labels: {
          app: 'openid',
          'app.kubernetes.io/part-of': 'openid',
        },
      },
      spec: {
        containers: [{
          name: 'openid',
          image: 'quay.io/calebdoxsey/reference-openid-provider:latest',
          imagePullPolicy: 'IfNotPresent',
          ports: [
            { name: 'http', containerPort: 6080 },
          ],
        }],
      },
    },
  },
};

local Ingress = function() {
  apiVersion: 'extensions/v1beta1',
  kind: 'Ingress',
  metadata: {
    namespace: 'default',
    name: 'openid',
    annotations: {
      'kubernetes.io/ingress.class': 'nginx',
      'nginx.ingress.kubernetes.io/backend-protocol': 'HTTP',
    },
  },
  spec: {
    tls: [
      {
        hosts: [
          'openid.localhost.pomerium.io',
        ],
        secretName: 'pomerium-trusted-tls',
      },
    ],
    rules: [
      {
        host: 'openid.localhost.pomerium.io',
        http: {
          paths: [
            {
              path: '/',
              backend: {
                serviceName: 'openid',
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
    Service(),
    Deployment(),
    Ingress(),
  ],
}
