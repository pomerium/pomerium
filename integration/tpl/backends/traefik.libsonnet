local utils = import '../utils.libsonnet';
local Routes = (import './routes.libsonnet').Routes;

local StaticConfig() =
  {
    global: {
      checkNewVersion: false,
      sendAnonymousUsage: false,
    },
    log: {
      level: 'DEBUG',
    },
    accessLog: {},
    entryPoints: {
      web: {
        address: ':80',
        forwardedheaders: {
          insecure: true,
        },
      },
      websecure: {
        address: ':443',
        forwardedheaders: {
          insecure: true,
        },
      },
    },
    api: {
      insecure: true,
    },
    providers: {
      file: {
        filename: 'traefik-dynamic.yaml',
      },
    },
  };

local Rule(route) =
  local url = utils.ParseURL(route.from);
  std.join(
    ' && ',
    ['Host(`' + url.host + '`)'] +
    (if std.objectHas(route, 'prefix') then
       ['PathPrefix(`' + route.prefix + '`)'] else []) +
    (if std.objectHas(route, 'path') then
       ['Path(`' + route.path + '`)'] else [])
  );

local DynamicConfig(mode, idp, dns_suffix='') =
  {
    local routes = Routes(mode, idp, dns_suffix) + [
      {
        from: 'https://authenticate.localhost.pomerium.io',
        to: 'https://pomerium' + dns_suffix + ':443',
        allow_public_unauthenticated_access: true,
        tls_skip_verify: true,
        preserve_host_header: true,
      },
    ],

    tls: {
      certificates: [{
        certFile: '_wildcard.localhost.pomerium.io.pem',
        keyFile: '_wildcard.localhost.pomerium.io-key.pem',
      }],
    },
    http: {
      serversTransports: {
        insecure: {
          insecureSkipVerify: true,
        },
      },
      routers: {
        ['route%d' % i]: {
          service: 'route%d' % i,
          rule: Rule(routes[i]),
          tls: {},
          middlewares:
            (if routes[i].from == 'https://authenticate.localhost.pomerium.io' then
               []
             else
               ['authz']) +
            (if std.objectHas(routes[i], 'set_request_headers') then
               ['set-request-headers-%d' % i]
             else
               []),
        }
        for i in std.range(0, std.length(routes) - 1)
      },
      services: {
        ['route%d' % i]: {
          loadBalancer:
            {
              servers: [{
                url: routes[i].to,
              }],
            } +
            (if std.startsWith(routes[i].to, 'https://') then
               { serversTransport: 'insecure' }
             else
               {}) +
            (if std.objectHas(routes[i], 'preserve_host_header') && routes[i].preserve_host_header then
               { passHostHeader: true }
             else
               { passHostHeader: false }),
        }
        for i in std.range(0, std.length(routes) - 1)
      },
      middlewares: {
        authz: {
          forwardAuth: {
            address: 'https://forward-authenticate.localhost.pomerium.io',
            trustForwardHeader: true,
            authResponseHeaders: ['x-pomerium-jwt-assertion', 'x-pomerium-claim-email', 'authorization'],
            tls: {
              insecureSkipVerify: true,
            },
          },
        },
      } + {
        ['set-request-headers-%d' % i]: {
          headers: {
            customRequestHeaders: {
              [k]: routes[i].set_request_headers[k]
              for k in std.objectFields(routes[i].set_request_headers)
            },
          },
        }
        for i in std.range(0, std.length(routes) - 1)
        if std.objectHas(routes[i], 'set_request_headers')
      },
    },
  };

local Command(mode, idp, dns_suffix='') =
  [
    'sh',
    '-c',
    |||
      cat <<-'END_OF_TRAEFIK' | tee traefik.yaml
      %s
      END_OF_TRAEFIK
      cat <<-'END_OF_TRAEFIK' | tee traefik-dynamic.yaml
      %s
      END_OF_TRAEFIK
      cat <<-'END_OF_TRAEFIK' | tee _wildcard.localhost.pomerium.io.pem
      %s
      END_OF_TRAEFIK
      cat <<-'END_OF_TRAEFIK' | tee _wildcard.localhost.pomerium.io-key.pem
      %s
      END_OF_TRAEFIK

      traefik -configFile=traefik.yaml
    ||| % [
      std.manifestJsonEx(StaticConfig(), '  '),
      std.manifestJsonEx(DynamicConfig(mode, idp, dns_suffix), '  '),
      importstr '../files/trusted.pem',
      importstr '../files/trusted-key.pem',
    ],
  ];

function(mode, idp, dns_suffix='') {
  local image = 'traefik:latest',
  compose: {
    services:
      utils.ComposeService('traefik', {
        image: image,
        depends_on: {
          pomerium: {
            condition: 'service_started',
          },
        },
        command: Command(mode, idp, dns_suffix),
        ports: [
          '80:80/tcp',
          '443:443/tcp',
        ],
      }, ['authenticate.localhost.pomerium.io', 'mock-idp.localhost.pomerium.io']),
  },
}
