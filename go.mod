module github.com/pomerium/pomerium

go 1.22

require (
	cloud.google.com/go/storage v1.39.0
	contrib.go.opencensus.io/exporter/jaeger v0.2.1
	contrib.go.opencensus.io/exporter/prometheus v0.4.2
	contrib.go.opencensus.io/exporter/zipkin v0.1.2
	github.com/CAFxX/httpcompression v0.0.9
	github.com/DataDog/opencensus-go-exporter-datadog v0.0.0-20200406135749-5c268882acf0
	github.com/VictoriaMetrics/fastcache v1.12.2
	github.com/aws/aws-sdk-go-v2 v1.25.2
	github.com/aws/aws-sdk-go-v2/config v1.27.6
	github.com/aws/aws-sdk-go-v2/service/s3 v1.51.3
	github.com/bits-and-blooms/bitset v1.13.0
	github.com/caddyserver/certmagic v0.20.0
	github.com/cenkalti/backoff/v4 v4.2.1
	github.com/cespare/xxhash/v2 v2.2.0
	github.com/cloudflare/circl v1.3.7
	github.com/coreos/go-oidc/v3 v3.9.0
	github.com/docker/docker v25.0.3+incompatible
	github.com/envoyproxy/go-control-plane v0.12.0
	github.com/envoyproxy/protoc-gen-validate v1.0.4
	github.com/go-chi/chi/v5 v5.0.12
	github.com/go-jose/go-jose/v3 v3.0.2
	github.com/golang/mock v1.6.0
	github.com/google/btree v1.1.2
	github.com/google/go-cmp v0.6.0
	github.com/google/go-jsonnet v0.20.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.1
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.0.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/jackc/pgx/v5 v5.5.3
	github.com/klauspost/compress v1.17.7
	github.com/martinlindhe/base36 v1.1.1
	github.com/mholt/acmez v1.2.0
	github.com/minio/minio-go/v7 v7.0.67
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/mitchellh/mapstructure v1.5.0
	github.com/natefinch/atomic v1.0.1
	github.com/oapi-codegen/runtime v1.1.1
	github.com/open-policy-agent/opa v0.62.1
	github.com/openzipkin/zipkin-go v0.4.2
	github.com/ory/dockertest/v3 v3.10.0
	github.com/peterbourgon/ff/v3 v3.4.0
	github.com/pomerium/csrf v1.7.0
	github.com/pomerium/datasource v0.18.2-0.20221108160055-c6134b5ed524
	github.com/pomerium/webauthn v0.0.0-20221118023040-00a9c430578b
	github.com/prometheus/client_golang v1.19.0
	github.com/prometheus/client_model v0.6.0
	github.com/prometheus/common v0.49.0
	github.com/prometheus/procfs v0.12.0
	github.com/rs/cors v1.10.1
	github.com/rs/zerolog v1.32.0
	github.com/shirou/gopsutil/v3 v3.24.2
	github.com/spf13/viper v1.18.2
	github.com/stretchr/testify v1.8.4
	github.com/tniswong/go.rfcx v0.0.0-20181019234604-07783c52761f
	github.com/volatiletech/null/v9 v9.0.0
	github.com/yuin/gopher-lua v1.1.1
	go.opencensus.io v0.24.0
	go.opentelemetry.io/otel v1.24.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v0.45.0
	go.opentelemetry.io/otel/metric v1.24.0
	go.opentelemetry.io/otel/sdk v1.24.0
	go.opentelemetry.io/otel/sdk/metric v1.24.0
	go.uber.org/automaxprocs v1.5.3
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.21.0
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa
	golang.org/x/net v0.22.0
	golang.org/x/oauth2 v0.18.0
	golang.org/x/sync v0.6.0
	golang.org/x/time v0.5.0
	google.golang.org/api v0.168.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240304161311-37d4d3c04a78
	google.golang.org/grpc v1.62.1
	google.golang.org/protobuf v1.33.0
	gopkg.in/yaml.v3 v3.0.1
	namespacelabs.dev/go-filenotify v0.0.0-20220511192020-53ea11be7eaa
	sigs.k8s.io/yaml v1.4.0
)

require (
	cloud.google.com/go v0.112.0 // indirect
	cloud.google.com/go/compute v1.24.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v1.1.6 // indirect
	dario.cat/mergo v1.0.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/DataDog/datadog-go v3.5.0+incompatible // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/agnivade/levenshtein v1.1.1 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.1 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.6 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.15.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.3.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.17.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.20.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.23.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.28.3 // indirect
	github.com/aws/smithy-go v1.20.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/census-instrumentation/opencensus-proto v0.4.1 // indirect
	github.com/cncf/xds/go v0.0.0-20231128003011-0fa0005c9caa // indirect
	github.com/containerd/continuity v0.4.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.5.0 // indirect
	github.com/docker/cli v25.0.3+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-sql-driver/mysql v1.7.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-tpm v0.3.3 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.12.2 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.16.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/lib/pq v1.10.7 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/miekg/dns v1.1.57 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc6 // indirect
	github.com/opencontainers/runc v1.1.12 // indirect
	github.com/pelletier/go-toml/v2 v2.1.0 // indirect
	github.com/philhofer/fwd v1.0.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/statsd_exporter v0.22.7 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rs/xid v1.5.0 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tchap/go-patricia/v2 v2.3.1 // indirect
	github.com/tinylib/msgp v1.1.2 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/uber/jaeger-client-go v2.25.0+incompatible // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.49.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.22.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.22.0 // indirect
	go.opentelemetry.io/otel/trace v1.24.0 // indirect
	go.opentelemetry.io/proto/otlp v1.0.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.15.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto v0.0.0-20240213162025-012b6fc9bca9 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240221002015-b0ce06bbee7c // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.22.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
