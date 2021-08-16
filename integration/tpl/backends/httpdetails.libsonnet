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

local command = function(variation) [
  'sh',
  '-c',
  |||
    cat <<-END_OF_HTTPDETAILS | tee /app/fullchain.pem
    %s
    END_OF_HTTPDETAILS
    cat <<-END_OF_HTTPDETAILS | tee /app/privkey.pem
    %s
    END_OF_HTTPDETAILS
    node ./index.js
  ||| % [variation.cert, variation.key],
];

function() {
  local suffix = 'httpdetails',
  local image = 'mendhak/http-https-echo:19',

  compose: {
    services: {
      [variation.name + '-' + suffix]: {
        image: image,
        command: command(variation),
      }
      for variation in variations
    },
  },
  kubernetes: std.foldl(
    function(acc, variation)
      acc + [
        {
          apiVersion: 'v1',
          kind: 'Service',
          metadata: {
            namespace: 'default',
            name: variation.name + '-' + suffix,
            labels: { app: variation.name + '-' + suffix },
          },
          spec: {
            selector: { app: variation.name + '-' + suffix },
            ports: [
              { name: 'http', port: 8080, targetPort: 'http' },
              { name: 'https', port: 8443, targetPort: 'https' },
            ],
          },
        },
        {
          apiVersion: 'apps/v1',
          kind: 'Deployment',
          metadata: {
            namespace: 'default',
            name: variation.name + '-' + suffix,
          },
          spec: {
            replicas: 1,
            selector: { matchLabels: { app: variation.name + '-' + suffix } },
            template: {
              metadata: {
                labels: { app: variation.name + '-' + suffix },
              },
              spec: {
                containers: [{
                  name: variation.name + '-' + suffix,
                  image: image,
                  args: command(variation),
                  ports: [
                    { name: 'http', containerPort: 8080 },
                    { name: 'https', containerPort: 8443 },
                  ],
                }],
              },
            },
          },
        },
      ], variations, []
  ),
}
