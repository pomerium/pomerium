local utils = import '../utils.libsonnet';

function(idp) utils.merge([
  (import '../backends/k3s.libsonnet')(
    idp,
    (import '../backends/fortio.libsonnet')().kubernetes +
    (import '../backends/mock-idp.libsonnet')(idp).kubernetes +
    (import '../backends/pomerium.libsonnet')(idp, '.default.svc.cluster.local').kubernetes +
    (import '../backends/websocket-echo.libsonnet')().kubernetes
  ).compose,
])
