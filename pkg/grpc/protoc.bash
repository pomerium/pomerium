#!/bin/bash

function join_by() {
  local IFS="$1"
  shift
  echo "$*"
}

_protos=(
  "envoy/annotations/deprecation.proto"
  "envoy/config/cluster/v3/circuit_breaker.proto"
  "envoy/config/cluster/v3/cluster.proto"
  "envoy/config/cluster/v3/filter.proto"
  "envoy/config/cluster/v3/outlier_detection.proto"
  "envoy/config/core/v3/address.proto"
  "envoy/config/core/v3/backoff.proto"
  "envoy/config/core/v3/base.proto"
  "envoy/config/core/v3/config_source.proto"
  "envoy/config/core/v3/event_service_config.proto"
  "envoy/config/core/v3/extension.proto"
  "envoy/config/core/v3/grpc_service.proto"
  "envoy/config/core/v3/health_check.proto"
  "envoy/config/core/v3/http_uri.proto"
  "envoy/config/core/v3/protocol.proto"
  "envoy/config/core/v3/proxy_protocol.proto"
  "envoy/config/core/v3/socket_option.proto"
  "envoy/config/endpoint/v3/endpoint_components.proto"
  "envoy/config/endpoint/v3/endpoint.proto"
  "envoy/config/route/v3/route_components.proto"
  "envoy/service/auth/v3/attribute_context.proto"
  "envoy/service/auth/v3/external_auth.proto"
  "envoy/type/matcher/v3/regex.proto"
  "envoy/type/matcher/v3/string.proto"
  "envoy/type/metadata/v3/metadata.proto"
  "envoy/type/tracing/v3/custom_tag.proto"
  "envoy/type/v3/http.proto"
  "envoy/type/v3/http_status.proto"
  "envoy/type/v3/percent.proto"
  "envoy/type/v3/range.proto"
  "envoy/type/v3/semantic_version.proto"
  "udpa/annotations/migrate.proto"
  "udpa/annotations/security.proto"
  "udpa/annotations/sensitive.proto"
  "udpa/annotations/status.proto"
  "udpa/annotations/versioning.proto"
  "xds/core/v3/authority.proto"
  "xds/core/v3/collection_entry.proto"
  "xds/core/v3/context_params.proto"
  "xds/core/v3/resource_locator.proto"
)
_imports=()
for _proto in "${_protos[@]}"; do
  _imports+=("M${_proto}=github.com/envoyproxy/go-control-plane/$(dirname "$_proto")")
done

_import_paths=$(join_by , "${_imports[@]}")

../../scripts/protoc -I ./audit/ \
  --go_out="$_import_paths,plugins=grpc,paths=source_relative:./audit/." \
  ./audit/audit.proto

../../scripts/protoc -I "$GOPATH/src" -I ./config/ \
  --go_out="$_import_paths,plugins=grpc,paths=source_relative:./config/." \
  ./config/config.proto

../../scripts/protoc -I ./crypt/ \
  --go_out="$_import_paths,plugins=grpc,paths=source_relative:./crypt/." \
  ./crypt/crypt.proto

../../scripts/protoc -I ./databroker/ \
  --go_out="$_import_paths,plugins=grpc,paths=source_relative:./databroker/." \
  ./databroker/databroker.proto

../../scripts/protoc -I ./directory/ \
  --go_out="$_import_paths,plugins=grpc,paths=source_relative:./directory/." \
  ./directory/directory.proto

../../scripts/protoc -I ./registry/ \
  --go_out="$_import_paths,plugins=grpc,paths=source_relative:./registry/." \
  --validate_out="lang=go,paths=source_relative:./registry" \
  ./registry/registry.proto

../../scripts/protoc -I ./session/ \
  --go_out="$_import_paths,plugins=grpc,paths=source_relative:./session/." \
  ./session/session.proto

../../scripts/protoc -I ./user/ \
  --go_out="$_import_paths,plugins=grpc,paths=source_relative:./user/." \
  ./user/user.proto
