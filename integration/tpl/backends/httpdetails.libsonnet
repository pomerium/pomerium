local variations = [
  {
    name: 'trusted',
    cert: importstr '../files/trusted.pem',
    key: importstr '../files/trusted-key.pem',
  },
  {
    name: 'untrusted',
    cert: importstr '../files/untrusted.pem',
    key: importstr '../files/untrusted-key.pem',
  },
  {
    name: 'wrongly-named',
    cert: importstr '../files/invalid.pem',
    key: importstr '../files/invalid-key.pem',
  },
];

function() {
  local name = 'httpdetails',
  local image = 'mendhak/http-https-echo:19',
  local command = [
    'sh',
    '-c',
    |||
      echo "$$CERT" >/app/fullchain.pem
      echo "$$KEY" >/app/privkey.pem
      node ./index.js
    |||,
  ],

  compose: {
    services: {
      [variation.name + '-' + name]: {
        image: image,
        command: command,
        environment: {
          CERT: variation.cert,
          KEY: variation.key,
        },
      }
      for variation in variations
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
