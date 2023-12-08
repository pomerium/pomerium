local utils = import '../utils.libsonnet';

function(idp, authentication_flow) utils.Merge([
  (import '../backends/fortio.libsonnet')().compose,
  (import '../backends/httpdetails.libsonnet')().compose,
  (import '../backends/mock-idp.libsonnet')(idp).compose,
  (import '../backends/pomerium.libsonnet')('single', idp, authentication_flow).compose,
  (import '../backends/postgres.libsonnet')().compose,
  (import '../backends/verify.libsonnet')('single').compose,
  (import '../backends/websocket-echo.libsonnet')().compose,
  {
    networks: {
      main: {
        ipam: {
          config: [{subnet: "172.20.0.0/16"}],
        },
      },
    },
  },
])
