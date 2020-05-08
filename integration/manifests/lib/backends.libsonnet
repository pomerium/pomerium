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
    ports: [{
      name: 'http',
      port: 80,
      targetPort: 'http',
    }],
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
        initContainers: [{
          name: 'init',
          image: 'node:14-stretch-slim',
          imagePullPolicy: 'IfNotPresent',
          args: ['bash', '-c', 'cp -rL /src/* /app/'],
          volumeMounts: [{
            name: 'src',
            mountPath: '/src',
          }, {
            name: 'app',
            mountPath: '/app',
          }],
        }],
        containers: [{
          name: name,
          image: 'node:14-stretch-slim',
          imagePullPolicy: 'IfNotPresent',
          args: ['bash', '-c', 'cd /app && npm install && node index.js'],
          ports: [{
            name: 'http',
            containerPort: 8080,
          }],
          volumeMounts: [{
            name: 'app',
            mountPath: '/app',
          }],
        }],
        volumes: [{
          name: 'src',
          configMap: {
            name: name,
          },
        }, {
          name: 'app',
          emptyDir: {},
        }],
      },
    },
  },
};

{
  apiVersion: 'v1',
  kind: 'List',
  items: [
    configMap('httpdetails', {
      'index.js': importstr '../../backends/httpdetails/index.js',
    }),
    service('httpdetails'),
    deployment('httpdetails'),

    configMap('ws-echo', {
      'package.json': importstr '../../backends/ws-echo/package.json',
      'index.js': importstr '../../backends/ws-echo/index.js',
    }),
    service('ws-echo'),
    deployment('ws-echo'),
  ],
}
