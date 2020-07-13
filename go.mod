module github.com/pomerium/pomerium

go 1.14

require (
	contrib.go.opencensus.io/exporter/jaeger v0.2.0
	contrib.go.opencensus.io/exporter/prometheus v0.2.0
	contrib.go.opencensus.io/exporter/zipkin v0.1.1
	github.com/btcsuite/btcutil v1.0.2
	github.com/caddyserver/certmagic v0.11.2
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/cespare/xxhash/v2 v2.1.1
	github.com/cncf/udpa/go v0.0.0-20200629203442-efcf912fb354 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/envoyproxy/go-control-plane v0.9.6
	github.com/fsnotify/fsnotify v1.4.9
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/golang/mock v1.4.3
	github.com/golang/protobuf v1.4.2
	github.com/google/btree v1.0.0
	github.com/google/go-cmp v0.5.0
	github.com/google/go-jsonnet v0.16.0
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/gorilla/websocket v1.4.2
	github.com/hashicorp/golang-lru v0.5.4
	github.com/hashicorp/memberlist v0.2.2
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/lithammer/shortuuid/v3 v3.0.4
	github.com/mitchellh/hashstructure v1.0.0
	github.com/natefinch/atomic v0.0.0-20200526193002-18c0533a5b09
	github.com/nsf/jsondiff v0.0.0-20200515183724-f29ed568f4ce
	github.com/onsi/ginkgo v1.11.0 // indirect
	github.com/onsi/gocleanup v0.0.0-20140331211545-c1a5478700b5
	github.com/onsi/gomega v1.8.1 // indirect
	github.com/open-policy-agent/opa v0.21.1
	github.com/openzipkin/zipkin-go v0.2.2
	github.com/pelletier/go-toml v1.6.0 // indirect
	github.com/pomerium/csrf v1.6.2-0.20190918035251-f3318380bad3
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/prometheus/client_golang v1.7.1
	github.com/rakyll/statik v0.1.7
	github.com/rcrowley/go-metrics v0.0.0-20190826022208-cac0b30c2563 // indirect
	github.com/rs/cors v1.7.0
	github.com/rs/zerolog v1.19.0
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1
	github.com/tomnomnom/linkheader v0.0.0-20180905144013-02ca5825eb80
	github.com/uber/jaeger-client-go v2.20.1+incompatible // indirect
	go.opencensus.io v0.22.4
	golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899
	golang.org/x/net v0.0.0-20200707034311-ab3426394381
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	google.golang.org/api v0.29.0
	google.golang.org/genproto v0.0.0-20200711021454-869866162049
	google.golang.org/grpc v1.30.0
	google.golang.org/protobuf v1.25.0
	gopkg.in/cookieo9/resources-go.v2 v2.0.0-20150225115733-d27c04069d0d
	gopkg.in/square/go-jose.v2 v2.5.1
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v2 v2.3.0
)
