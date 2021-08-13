local utils = import '../utils.libsonnet';

function(idp) utils.merge([
  (import '../backends/k3s.libsonnet')(
    idp,
    (import '../backends/fortio.libsonnet')().kubernetes +
    (import '../backends/websocket-echo.libsonnet')().kubernetes
  ).compose,
])
