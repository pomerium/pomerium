local utils = import '../utils.libsonnet';

function() {
  local name = 'websocket-echo',
  local image = 'pvtmert/websocketd:latest',
  local command = ['--port', '80', 'tee'],

  compose: {
    services:
      utils.ComposeService(name, {
        image: image,
        command: command,
      }) +
      utils.ComposeService(name + '-ready', {
        image: 'jwilder/dockerize:0.6.1',
        command: [
          '-wait',
          'tcp://' + name + ':80',
          '-timeout',
          '10m',
        ],
      }),
    volumes: {},
  },
  kubernetes: [
    utils.KubernetesDeployment(name, {
      image: image,
      args: command,
      ports: [
        { name: 'http', containerPort: 80 },
      ],
    }),
    utils.KubernetesService(name, [
      { name: 'http', port: 80, targetPort: 'http' },
    ]),
  ],
}
