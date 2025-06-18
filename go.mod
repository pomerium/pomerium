module github.com/pomerium/pomerium

go 1.24.0

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.6-20250425153114-8976f5be98c1.1
	cloud.google.com/go/storage v1.55.0
	contrib.go.opencensus.io/exporter/prometheus v0.4.2
	github.com/CAFxX/httpcompression v0.0.9
	github.com/VictoriaMetrics/fastcache v1.12.4
	github.com/aws/aws-sdk-go-v2 v1.36.3
	github.com/aws/aws-sdk-go-v2/config v1.29.14
	github.com/aws/aws-sdk-go-v2/service/s3 v1.80.0
	github.com/bits-and-blooms/bitset v1.22.0
	github.com/bufbuild/protovalidate-go v0.10.1
	github.com/caddyserver/certmagic v0.23.0
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/charmbracelet/bubbles v0.21.0
	github.com/charmbracelet/bubbletea v1.3.4
	github.com/charmbracelet/lipgloss v1.1.0
	github.com/charmbracelet/x/ansi v0.8.0
	github.com/cloudflare/circl v1.6.1
	github.com/cncf/xds/go v0.0.0-20250326154945-ae57f3c0d45f
	github.com/cockroachdb/pebble/v2 v2.0.4
	github.com/coreos/go-oidc/v3 v3.14.1
	github.com/docker/docker v28.2.2+incompatible
	github.com/envoyproxy/go-control-plane/envoy v1.32.4
	github.com/envoyproxy/protoc-gen-validate v1.2.1
	github.com/exaring/otelpgx v0.9.4-0.20250625070127-170cf59316c5
	github.com/fsnotify/fsnotify v1.9.0
	github.com/gaissmai/bart v0.20.4
	github.com/go-chi/chi/v5 v5.2.1
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/go-viper/mapstructure/v2 v2.3.0
	github.com/google/btree v1.1.3
	github.com/google/go-cmp v0.7.0
	github.com/google/go-jsonnet v0.21.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.3
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.3.2
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-set/v3 v3.0.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/jackc/pgx/v5 v5.7.5
	github.com/jxskiss/base62 v1.1.0
	github.com/klauspost/compress v1.18.0
	github.com/martinlindhe/base36 v1.1.1
	github.com/mholt/acmez/v3 v3.1.2
	github.com/miekg/dns v1.1.66
	github.com/minio/minio-go/v7 v7.0.92
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c
	github.com/natefinch/atomic v1.0.1
	github.com/oapi-codegen/runtime v1.1.1
	github.com/open-policy-agent/opa v1.5.0
	github.com/peterbourgon/ff/v3 v3.4.0
	github.com/pires/go-proxyproto v0.8.1
	github.com/pomerium/csrf v1.7.0
	github.com/pomerium/datasource v0.18.2-0.20221108160055-c6134b5ed524
	github.com/pomerium/envoy-custom v1.34.1-rc2.0.20250625214310-c029d58dae62
	github.com/pomerium/protoutil v0.0.0-20240813175624-47b7ac43ff46
	github.com/pomerium/webauthn v0.0.0-20240603205124-0428df511172
	github.com/prometheus/client_golang v1.22.0
	github.com/prometheus/client_model v0.6.2
	github.com/prometheus/common v0.64.0
	github.com/prometheus/procfs v0.16.1
	github.com/quic-go/quic-go v0.52.0
	github.com/rs/cors v1.11.1
	github.com/rs/zerolog v1.34.0
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	github.com/stretchr/testify v1.10.0
	github.com/testcontainers/testcontainers-go v0.37.0
	github.com/tidwall/gjson v1.18.0
	github.com/tniswong/go.rfcx v0.0.0-20181019234604-07783c52761f
	github.com/volatiletech/null/v9 v9.0.0
	github.com/yuin/gopher-lua v1.1.1
	github.com/zeebo/xxh3 v1.0.2
	go.opencensus.io v0.24.0
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.61.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0
	go.opentelemetry.io/contrib/propagators/autoprop v0.61.0
	go.opentelemetry.io/otel v1.36.0
	go.opentelemetry.io/otel/bridge/opencensus v1.36.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.36.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.36.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.36.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.36.0
	go.opentelemetry.io/otel/exporters/prometheus v0.58.0
	go.opentelemetry.io/otel/metric v1.36.0
	go.opentelemetry.io/otel/sdk v1.36.0
	go.opentelemetry.io/otel/sdk/metric v1.36.0
	go.opentelemetry.io/otel/trace v1.36.0
	go.opentelemetry.io/proto/otlp v1.7.0
	go.uber.org/automaxprocs v1.6.0
	go.uber.org/mock v0.5.2
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.39.0
	golang.org/x/net v0.41.0
	golang.org/x/oauth2 v0.30.0
	golang.org/x/sync v0.15.0
	golang.org/x/sys v0.33.0
	golang.org/x/time v0.11.0
	google.golang.org/api v0.235.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250528174236-200df99c418a
	google.golang.org/grpc v1.72.2
	google.golang.org/protobuf v1.36.6
	gopkg.in/yaml.v3 v3.0.1
	sigs.k8s.io/yaml v1.4.0
)

require (
	cel.dev/expr v0.23.1 // indirect
	cloud.google.com/go v0.121.1 // indirect
	cloud.google.com/go/auth v0.16.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.7.0 // indirect
	cloud.google.com/go/iam v1.5.2 // indirect
	cloud.google.com/go/monitoring v1.24.2 // indirect
	dario.cat/mergo v1.0.1 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/DataDog/zstd v1.5.6-0.20230824185856-869dae002e5e // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.27.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.51.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.51.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/agnivade/levenshtein v1.2.1 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.10 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.67 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.7.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.19 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/caddyserver/zerossl v0.1.3 // indirect
	github.com/cenkalti/backoff/v5 v5.0.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/colorprofile v0.2.3-0.20250311203215-f60798e515dc // indirect
	github.com/charmbracelet/x/cellbuf v0.0.13-0.20250311204145-2c3ea96c31dd // indirect
	github.com/charmbracelet/x/term v0.2.1 // indirect
	github.com/cockroachdb/crlib v0.0.0-20241015224233-894974b3ad94 // indirect
	github.com/cockroachdb/errors v1.11.3 // indirect
	github.com/cockroachdb/fifo v0.0.0-20240606204812-0bbfbd93a7ce // indirect
	github.com/cockroachdb/logtags v0.0.0-20230118201751-21c54148d20b // indirect
	github.com/cockroachdb/redact v1.1.5 // indirect
	github.com/cockroachdb/swiss v0.0.0-20250304010804-34a2c6a59016 // indirect
	github.com/cockroachdb/tokenbucket v0.0.0-20230807174530-cc333fc44b06 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.1 // indirect
	github.com/cpuguy83/dockercfg v0.3.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ebitengine/purego v0.8.2 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/getsentry/sentry-go v0.27.0 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.5 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.6.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/snappy v0.0.5-0.20231225225746-43d5d4cd4e0e // indirect
	github.com/google/cel-go v0.25.0 // indirect
	github.com/google/go-tpm v0.9.0 // indirect
	github.com/google/pprof v0.0.0-20240424215950-a892ee059fd6 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.14.2 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/kralicky/go-adaptive-radix-tree v0.0.0-20240624235931-330eb762e74c // indirect
	github.com/libdns/libdns v1.0.0-beta.1 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20240513124658-fba389f38bae // indirect
	github.com/magiconair/properties v1.8.10 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/minio/crc64nvme v1.0.1 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/go-archive v0.1.0 // indirect
	github.com/moby/patternmatcher v0.6.0 // indirect
	github.com/moby/sys/atomicwriter v0.1.0 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/onsi/ginkgo/v2 v2.19.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/philhofer/fwd v1.1.3-0.20240916144458-20a13a1f6b7c // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/prometheus/statsd_exporter v0.22.7 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/sahilm/fuzzy v0.1.1 // indirect
	github.com/shirou/gopsutil/v4 v4.25.1 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/spiffe/go-spiffe/v2 v2.5.0 // indirect
	github.com/sryoya/protorand v0.0.0-20240429201223-e7440656b2a4 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tchap/go-patricia/v2 v2.3.2 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tinylib/msgp v1.3.0 // indirect
	github.com/tklauser/go-sysconf v0.3.14 // indirect
	github.com/tklauser/numcpus v0.8.0 // indirect
	github.com/vektah/gqlparser/v2 v2.5.26 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zeebo/assert v1.3.1 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	github.com/zeebo/errs v1.4.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.36.0 // indirect
	go.opentelemetry.io/contrib/propagators/aws v1.36.0 // indirect
	go.opentelemetry.io/contrib/propagators/b3 v1.36.0 // indirect
	go.opentelemetry.io/contrib/propagators/jaeger v1.36.0 // indirect
	go.opentelemetry.io/contrib/propagators/ot v1.36.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	golang.org/x/exp v0.0.0-20241108190413-2d47ceb2692f // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	golang.org/x/tools v0.34.0 // indirect
	google.golang.org/genproto v0.0.0-20250505200425-f936aa4a68b2 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250528174236-200df99c418a // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
