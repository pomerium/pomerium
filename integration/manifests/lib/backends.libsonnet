local configMap = function(name, data) {
  apiVersion: 'v1',
  kind: 'ConfigMap',
  metadata: {
    namespace: 'default',
    name: name,
    labels: {
      app: name,
    },
  },
  data: data,
};

local service = function(name, tlsName, requireMutualAuth) {
  local fullName = (if tlsName != null then tlsName + '-' else '') +
                   (if requireMutualAuth then 'mtls-' else '') +
                   name,

  apiVersion: 'v1',
  kind: 'Service',
  metadata: {
    namespace: 'default',
    name: fullName,
    labels: { app: fullName },
  },
  spec: {
    selector: { app: fullName },
    ports: [
      {
        name: 'http',
        port: 80,
        targetPort: 'http',
      },
      {
        name: 'https',
        port: 443,
        targetPort: 'https',
      },
    ],
  },
};

local deployment = function(name, tlsName, requireMutualAuth) {
  local fullName = (if tlsName != null then tlsName + '-' else '') +
                   (if requireMutualAuth then 'mtls-' else '') +
                   name,

  apiVersion: 'apps/v1',
  kind: 'Deployment',
  metadata: {
    namespace: 'default',
    name: fullName,
  },
  spec: {
    replicas: 1,
    selector: { matchLabels: { app: fullName } },
    template: {
      metadata: {
        labels: { app: fullName },
      },
      spec: {
        containers: [{
          name: 'main',
          image: 'golang:buster',
          imagePullPolicy: 'IfNotPresent',
          args: [
            'bash',
            '-c',
            'cd /src && go run . ' +
            (if tlsName != null then
               '-cert-file=/certs/tls.crt -key-file=/certs/tls.key'
             else
               '') +
            (if requireMutualAuth then
               '-mutual-auth-ca-file=/certs/tls.ca'
             else
               ''),
          ],
          ports: [
            {
              name: 'http',
              containerPort: 5080,
            },
            {
              name: 'https',
              containerPort: 5443,
            },
          ],
          volumeMounts: [
            {
              name: 'src',
              mountPath: '/src',
            },
            {
              name: 'certs',
              mountPath: '/certs',
            },
          ],
        }],
        volumes: [
          {
            name: 'src',
            configMap: {
              name: name,
            },
          },
        ] + if tlsName != null then [
          {
            name: 'certs',
            secret: {
              secretName: 'pomerium-' + tlsName + '-tls',
            },
          },
        ] else [
          {
            name: 'certs',
            emptyDir: {},
          },
        ],
      },
    },
  },
};

local backends = [
  { name: 'httpdetails', files: {
    'main.go': importstr '../../backends/httpdetails/main.go',
    'go.mod': importstr '../../backends/httpdetails/go.mod',
  } },
  { name: 'ws-echo', files: {
    'main.go': importstr '../../backends/ws-echo/main.go',
    'go.mod': importstr '../../backends/ws-echo/go.mod',
    'go.sum': importstr '../../backends/ws-echo/go.sum',
  } },
];

{
  apiVersion: 'v1',
  kind: 'List',
  items: std.flattenArrays(
    [
      [
        configMap(backend.name, backend.files),
        service(backend.name, null, false),
        deployment(backend.name, null, false),
        service(backend.name, null, true),
        deployment(backend.name, null, true),
        service(backend.name, 'wrongly-named', false),
        deployment(backend.name, 'wrongly-named', false),
        service(backend.name, 'untrusted', false),
        deployment(backend.name, 'untrusted', false),
      ]
      for backend in backends
    ]
  ),
}
