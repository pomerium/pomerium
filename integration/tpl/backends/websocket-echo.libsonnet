function() {
  local name = 'websocket-echo',
  local image = 'pvtmert/websocketd:latest',
  local command = ['--port', '80', 'tee'],

  compose: {
    services: {
      [name]: {
        image: image,
        command: command,
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
          { name: 'http', port: 80, targetPort: 'http' },
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
                { name: 'http', containerPort: 80 },
              ],
            }],
          },
        },
      },
    },
  ],
}
