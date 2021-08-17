function(idp) {
  local name = 'mock-idp',
  local image = 'calebdoxsey/mock-idps:${MOCK_IDPS_TAG:-master}',
  local command = [
    '--provider',
    idp,
    '--port',
    '8024',
    '--root-url',
    'https://mock-idp.localhost.pomerium.io/',
  ],

  compose: {
    services: {
      [name]: {
        image: image,
        command: command,
        ports: [
          '8024:8024/tcp',
        ],
      },
    },
    volumes: {},
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
          { name: 'http', port: 8024, targetPort: 'http' },
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
              args: command,
              ports: [
                { name: 'http', containerPort: 8024 },
              ],
            }],
          },
        },
      },
    },
  ],
}
