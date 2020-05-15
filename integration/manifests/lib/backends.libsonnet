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

local service = function(name) {
  apiVersion: 'v1',
  kind: 'Service',
  metadata: {
    namespace: 'default',
    name: name,
    labels: { app: name },
  },
  spec: {
    selector: { app: name },
    ports: [
      {
        name: 'http',
        port: 80,
        targetPort: 'http',
      },
      {
        name: 'https',
        port: 80,
        targetPort: 'https',
      },
    ],
  },
};

local deployment = function(name) {
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
          image: 'golang:buster',
          imagePullPolicy: 'IfNotPresent',
          args: [
            'bash',
            '-c',
            |||
              cd /src
              go run .
            |||,
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
          ],
        }],
        volumes: [
          {
            name: 'src',
            configMap: {
              name: name,
            },
          },
        ],
      },
    },
  },
};

{
  apiVersion: 'v1',
  kind: 'List',
  items: [
    configMap('httpdetails', {
      'main.go': importstr '../../backends/httpdetails/main.go',
      'go.mod': importstr '../../backends/httpdetails/go.mod',
    }),
    service('httpdetails'),
    deployment('httpdetails'),

    configMap('ws-echo', {
      'main.go': importstr '../../backends/ws-echo/main.go',
      'go.mod': importstr '../../backends/ws-echo/go.mod',
      'go.sum': importstr '../../backends/ws-echo/go.sum',
    }),
    service('ws-echo'),
    deployment('ws-echo'),
  ],
}
