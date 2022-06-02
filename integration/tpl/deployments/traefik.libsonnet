local utils = import '../utils.libsonnet';

function(idp) utils.Merge([
  (import '../backends/fortio.libsonnet')().compose,
  (import '../backends/httpdetails.libsonnet')().compose,
  (import '../backends/mock-idp.libsonnet')(idp).compose,
  (import '../backends/pomerium.libsonnet')('traefik', idp).compose,
  (import '../backends/postgres.libsonnet')().compose,
  (import '../backends/traefik.libsonnet')('single', idp).compose,
  (import '../backends/verify.libsonnet')('traefik').compose,
  (import '../backends/websocket-echo.libsonnet')().compose,
  {
    networks: {
      main: {},
    },
  },
])
