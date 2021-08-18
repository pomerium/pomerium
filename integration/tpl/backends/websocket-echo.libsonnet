local utils = import '../utils.libsonnet';

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
    utils.KubernetesDeployment(name, image, command, [
      { name: 'http', containerPort: 80 },
    ]),
    utils.KubernetesService(name, [
      { name: 'http', port: 80, targetPort: 'http' },
    ]),
  ],
}
