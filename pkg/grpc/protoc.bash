#!/bin/bash

function join_by() {
  local IFS="$1"
  shift
  echo "$*"
}

_sub_directories=(
  cli
  config
  databroker
  device
  events
  identity
  registry
  session
  user
  testproto
)

for _d in "${_sub_directories[@]}"; do
  ../../scripts/protoc -I "./$_d/" -I "./" \
    --go_out="./$_d" \
    --go_opt="paths=source_relative" \
    --go-grpc_out="./$_d" \
    --go-grpc_opt="paths=source_relative" \
    --go-grpc_opt="require_unimplemented_servers=false" \
    "${_imports[@]}" \
    "./$_d/"*.proto
done

../../scripts/protoc -I "./registry/" \
  --validate_out="./registry/" \
  --validate_opt="lang=go" \
  --validate_opt="paths=source_relative" \
  ./registry/registry.proto
