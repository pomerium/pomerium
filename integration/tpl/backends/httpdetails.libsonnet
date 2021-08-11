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
  services: {
    [variation.name + '-httpdetails']: {
      image: 'mendhak/http-https-echo:19',
      command: [
        'sh',
        '-c',
        |||
          echo "$$CERT" >/app/fullchain.pem
          echo "$$KEY" >/app/privkey.pem
          node ./index.js
        |||,
      ],
      environment: {
        CERT: variation.cert,
        KEY: variation.key,
      },
    }
    for variation in variations
  },
}
