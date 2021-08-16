function() {
  local name = 'redis',
  local image = 'redis:6.2.5-alpine',

  compose: {
    services: {
      redis: {
        image: image,
      },
    },
  },
  kubernetes: [
    {
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
          { name: 'tcp', port: 6379, targetPort: 'tcp' },
        ],
      },
    },
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
              ports: [
                { name: 'tcp', containerPort: 6379 },
              ],
            }],
          },
        },
      },
    },
  ],
}
