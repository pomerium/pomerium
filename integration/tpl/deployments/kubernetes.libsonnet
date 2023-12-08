local utils = import '../utils.libsonnet';

function(idp) utils.Merge([
  (import '../backends/k3s.libsonnet')(
    idp,
    (import '../backends/fortio.libsonnet')().kubernetes +
    (import '../backends/httpdetails.libsonnet')().kubernetes +
    (import '../backends/mock-idp.libsonnet')(idp).kubernetes +
    (import '../backends/pomerium.libsonnet')('single', idp, 'stateful', '.default.svc.cluster.local').kubernetes +
    (import '../backends/postgres.libsonnet')().kubernetes +
    (import '../backends/verify.libsonnet')('single').kubernetes +
    (import '../backends/websocket-echo.libsonnet')().kubernetes
  ).compose,
  {
    networks: {
      main: {},
    },
  },
])
