local utils = import '../utils.libsonnet';
local Routes = (import './routes.libsonnet').Routes;

local ProxyConfig() =
  |||
    set $pass_access_scheme $scheme;

    set $pass_server_port $server_port;

    set $best_http_host $http_host;
    set $pass_port $pass_server_port;

    set $proxy_alternative_upstream_name "";

    client_max_body_size 1m;


    proxy_set_header Host $best_http_host;

    # Pass the extracted client certificate to the backend

    # Allow websocket connections
    proxy_set_header Upgrade $http_upgrade;

    proxy_set_header Connection "";

    # uncomment to emulate nginx-ingress
    # set_escape_uri $escaped_request_uri $request_uri;

    # proxy_set_header X-Request-ID $req_id;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Host $best_http_host;
    proxy_set_header X-Forwarded-Port $pass_port;
    proxy_set_header X-Forwarded-Proto $pass_access_scheme;

    proxy_set_header X-Scheme $pass_access_scheme;

    # Pass the original X-Forwarded-For
    proxy_set_header X-Original-Forwarded-For $http_x_forwarded_for;

    # mitigate HTTPoxy Vulnerability
    # https://www.nginx.com/blog/mitigating-the-httpoxy-vulnerability-with-nginx/
    proxy_set_header Proxy "";

    # Custom headers to proxied server

    proxy_connect_timeout 5s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;

    proxy_buffering off;
    proxy_buffer_size 4k;
    proxy_buffers 4 4k;

    proxy_max_temp_file_size 1024m;

    proxy_request_buffering on;
    proxy_http_version 1.1;

    proxy_cookie_domain off;
    proxy_cookie_path off;

    # In case of errors try the next upstream server before returning an error
    proxy_next_upstream error timeout;
    proxy_next_upstream_timeout 0;
    proxy_next_upstream_tries 3;

    proxy_redirect off;
  |||;

local AuthenticateConfig() =
  |||
    # Pomerium endpoint
    server {
        listen 443 ssl;
        server_name  authenticate.localhost.pomerium.io forward-authenticate.localhost.pomerium.io;
        ssl_certificate /etc/_wildcard.localhost.pomerium.io.pem;
        ssl_certificate_key /etc/_wildcard.localhost.pomerium.io-key.pem;

        location / {
          proxy_pass https://pomerium;
          include /etc/nginx/proxy.conf;
        }
    }

    # Define an upstream so that we don't need resolvers when we use variables in proxy_pass directives
    # https://stackoverflow.com/questions/17685674/nginx-proxy-pass-with-remote-addr
    upstream pomerium {
        server pomerium:443;
    }
  |||;

local AuthzConfig() =
  |||
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-Proto "";

    proxy_set_header Host forward-authenticate.localhost.pomerium.io;
    proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Real-IP $remote_addr;

    proxy_set_header X-Forwarded-For $remote_addr;

    proxy_set_header X-Auth-Request-Redirect $request_uri;

    proxy_buffering off;

    proxy_buffer_size 256k;
    proxy_buffers 4 256k;
    proxy_busy_buffers_size 256k;
    proxy_request_buffering on;
    proxy_http_version 1.1;

    proxy_ssl_server_name on;
    proxy_pass_request_headers on;

    client_max_body_size 1m;

    # Pass the extracted client certificate to the auth provider

    set $target https://pomerium/verify?uri=$scheme://$http_host$request_uri;

    # uncomment to emulate nginx-ingress behavior
    # set $target https://pomerium/verify?uri=$scheme://$http_host$request_uri&rd=$pass_access_scheme://$http_host$escaped_request_uri;
    proxy_pass $target;
  |||;

local RouteLocationConfig(route) =
  local rule =
    if std.objectHas(route, 'prefix') then '^~ ' + route.prefix
    else if std.objectHas(route, 'path') then '= ' + route.path
    else '/';
  |||
    location %s {
      proxy_pass %s;

      include /etc/nginx/proxy.conf;
      # If we get a 401, respond with a named location
      error_page 401 = @authredirect;
      # this location requires authentication
      auth_request /ext_authz;
      auth_request_set $auth_cookie $upstream_http_set_cookie;
      add_header Set-Cookie $auth_cookie;
    }
  ||| % [rule, route.to];

local DomainServerConfig(domain, routes) =
  local locations = std.join('\n', std.map(function(route) RouteLocationConfig(route), routes));
  |||
    server {
      listen 443 ssl http2;
      server_name %s;
      ssl_certificate /etc/_wildcard.localhost.pomerium.io.pem;
      ssl_certificate_key /etc/_wildcard.localhost.pomerium.io-key.pem;

      location = /ext_authz {
        internal;
        include /etc/nginx/authz.conf;
      }

      location @authredirect {
        internal;
        add_header Set-Cookie $auth_cookie;

        # uncomment to emulate nginx-ingress behavior
        # return 302 https://forward-authenticate.localhost.pomerium.io/?uri=$scheme://$host$request_uri&rd=$pass_access_scheme://$http_host$escaped_request_uri;

        return 302
          https://forward-authenticate.localhost.pomerium.io/?uri=$scheme://$host$request_uri;
      }

      %s
    }
  ||| % [domain, locations];

local RoutesConfig(mode, idp, dns_suffix) =
  local routes = Routes(mode, idp, dns_suffix);
  local domains = std.set(std.map(function(route) utils.ParseURL(route.from).host, routes));
  std.join('\n', [
    local routesForDomain = std.filter(function(route)
                                         local url = utils.ParseURL(route.from);
                                         url.host == domain && (url.scheme == 'http' || url.scheme == 'https'),
                                       routes);
    DomainServerConfig(domain, routesForDomain)
    for domain in domains
  ]);

local WriteFile(path, contents) =
  |||
    cat <<-'END_OF_NGINX' | tee %s
    %s
    END_OF_NGINX
  ||| % [path, std.strReplace(contents, '$', '$$')];

local Command(mode, idp, dns_suffix) =
  [
    'sh',
    '-c',
    std.join('\n\n', [
      WriteFile('/etc/nginx/conf.d/authenticate.conf', AuthenticateConfig()),
      WriteFile('/etc/nginx/conf.d/routes.conf', RoutesConfig(mode, idp, dns_suffix)),
      WriteFile('/etc/nginx/authz.conf', AuthzConfig()),
      WriteFile('/etc/nginx/proxy.conf', ProxyConfig()),
      WriteFile('/etc/_wildcard.localhost.pomerium.io.pem', importstr '../files/trusted.pem'),
      WriteFile('/etc/_wildcard.localhost.pomerium.io-key.pem', importstr '../files/trusted-key.pem'),
      "nginx -g 'daemon off;'",
    ]),
  ];

function(mode, idp, dns_suffix='') {
  local image = 'nginx:1.21.1',

  compose: {
    services: {
      nginx: {
        image: image,
        entrypoint: Command(mode, idp, dns_suffix),
        ports: [
          '80:80/tcp',
          '443:443/tcp',
        ],
        links: [
          'pomerium:authenticate.localhost.pomerium.io',
          'pomerium:forward-authenticate.localhost.pomerium.io',
        ],
      },
    },
  },
}
