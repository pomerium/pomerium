function(multi) {
  local name = 'verify',
  local image = 'pomerium/verify:${VERIFY_TAG:-latest}',

  compose: {
    services: {
      verify: {
        image: image,
        depends_on: {
          verify_init: {
            condition: 'service_completed_successfully',
          },
        },
        environment: {
          SSL_CERT_FILE: '/verify_config/ca.pem',
        },
        links: if multi then [
          'pomerium-authenticate:authenticate.localhost.pomerium.io',
        ] else [
          'pomerium:authenticate.localhost.pomerium.io',
        ],
        volumes: [
          'verify_config:/verify_config',
        ],
      },
      verify_init: {
        image: 'busybox:latest',
        command: [
          'sh',
          '-c',
          "echo '" + (importstr '../files/ca.pem') + "' > /verify_config/ca.pem",
        ],
        volumes: [
          'verify_config:/verify_config',
        ],
      },
    },
    volumes: {
      verify_config: {},
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
