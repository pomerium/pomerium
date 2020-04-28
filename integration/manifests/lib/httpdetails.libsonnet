{
  apiVersion: 'v1',
  kind: 'List',
  items: [
    {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        namespace: 'default',
        name: 'httpdetails',
        labels: {
          app: 'httpdetails',
        },
      },
      data: {
        'index.js': importstr '../../backends/httpdetails/index.js',
      },
    },
    {
      apiVersion: 'v1',
      kind: 'Service',
      metadata: {
        namespace: 'default',
        name: 'httpdetails',
        labels: { app: 'httpdetails' },
      },
      spec: {
        selector: { app: 'httpdetails' },
        ports: [{
          name: 'http',
          port: 80,
          targetPort: 'http',
        }],
      },
    },
    {
      apiVersion: 'apps/v1',
      kind: 'Deployment',
      metadata: {
        namespace: 'default',
        name: 'httpdetails',
      },
      spec: {
        replicas: 1,
        selector: { matchLabels: { app: 'httpdetails' } },
        template: {
          metadata: {
            labels: { app: 'httpdetails' },
          },
          spec: {
            containers: [{
              name: 'httpbin',
              image: 'node:14-stretch-slim',
              imagePullPolicy: 'IfNotPresent',
              args: [
                'node',
                '/app/index.js',
              ],
              ports: [{
                name: 'http',
                containerPort: 8080,
              }],
              volumeMounts: [{
                name: 'httpdetails',
                mountPath: '/app',
              }],
            }],
            volumes: [{
              name: 'httpdetails',
              configMap: {
                name: 'httpdetails',
              },
            }],
          },
        },
      },
    },
  ],
}
