local utils = import '../utils.libsonnet';

local Variations() =
  [
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
    services: {
      [variation.name + '-' + suffix]: {
        image: image,
        command: Command(variation),
      }
      for variation in Variations()
    },
  },
  kubernetes: std.foldl(
    function(acc, variation)
      acc + [
        utils.KubernetesDeployment(variation.name + '-' + suffix, image, Command(variation), [
          { name: 'http', containerPort: 8080 },
          { name: 'https', containerPort: 8443 },
        ]),
        utils.KubernetesService(variation.name + '-' + suffix, [
          { name: 'http', port: 8080, targetPort: 'http' },
          { name: 'https', port: 8443, targetPort: 'https' },
        ]),
      ], Variations(), []
  ),
}
