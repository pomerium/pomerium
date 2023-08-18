local utils = import '../utils.libsonnet';

local Variations() =
  [
    {
      name: 'trusted',
      cert: importstr '../files/trusted-sans.pem',
      key: importstr '../files/trusted-sans-key.pem',
      ipv4Address: '172.20.0.50',
    },
    {
      name: 'trusted-1',
      cert: importstr '../files/trusted.pem',
      key: importstr '../files/trusted-key.pem',
    },
    {
      name: 'trusted-2',
      cert: importstr '../files/trusted.pem',
      key: importstr '../files/trusted-key.pem',
    },
    {
      name: 'trusted-3',
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

local Command(variation) =
  [
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
    services: std.foldl(
      function(acc, variation)
        acc +
        utils.ComposeService(variation.name + '-' + suffix, {
          image: image,
          command: Command(variation),
          [if std.get(variation, 'ipv4Address') != null then 'networks']: {
            main: {
              ipv4_address: variation.ipv4Address,
            }
          },
        }) +
        utils.ComposeService(variation.name + '-' + suffix + '-ready', {
          image: 'jwilder/dockerize:0.6.1',
          command: [
            '-wait',
            'http://' + variation.name + '-' + suffix + ':8080',
            '-timeout',
            '10m',
          ],
        }),
      Variations(),
      {}
    ),

  },
  kubernetes: std.foldl(
    function(acc, variation)
      acc + [
        utils.KubernetesDeployment(variation.name + '-' + suffix, {
          image: image,
          args: Command(variation),
          ports: [
            { name: 'http', containerPort: 8080 },
            { name: 'https', containerPort: 8443 },
          ],
        }),
        utils.KubernetesService(variation.name + '-' + suffix, [
          { name: 'http', port: 8080, targetPort: 'http' },
          { name: 'https', port: 8443, targetPort: 'https' },
        ]),
      ], Variations(), []
  ),
}
