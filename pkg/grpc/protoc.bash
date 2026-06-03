#!/bin/bash

_tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$_tmp_dir"' EXIT

function join_by() {
	local IFS="$1"
	shift
	echo "$*"
}

_dirs=(
	cli
	config
	databroker
	device
	events
	health
	identity
	registry
	session
	user
	testproto
)

for _d in "${_dirs[@]}"; do
	../../scripts/protoc \
		-I "./$_d/" \
		-I "./" \
		--go_out="./$_d" \
		--go_opt="paths=source_relative" \
		--go-grpc_out="./$_d" \
		--go-grpc_opt="paths=source_relative" \
		--go-grpc_opt="require_unimplemented_servers=false" \
		--doc_out="./$_d" \
		--doc_opt="json,$_d.pb.json" \
		"./$_d/"*.proto
done

_validate_dirs=(
	config
	registry
)

for _d in "${_validate_dirs[@]}"; do
	../../scripts/protoc \
		-I "./$_d/" \
		--validate_out="./$_d/" \
		--validate_opt="lang=go" \
		--validate_opt="paths=source_relative" \
		"./$_d/"*.proto
done

_connect_dirs=(
	config
)

_version="$(git describe --tags --abbrev=0)"
_version="${_version#v}"
cat <<EOF >"$_tmp_dir/base-openapi.yaml"
openapi: 3.1.0
info:
  version: $_version
EOF

for _d in "${_connect_dirs[@]}"; do
	../../scripts/protoc \
		-I "./$_d/" \
		--connect-go_out="./$_d/" \
		--connect-go_opt="paths=source_relative" \
		--connect-openapi_out="./$_d/" \
		--connect-openapi_opt="allow-get,content-types=json,trim-unused-types,base=$_tmp_dir/base-openapi.yaml,features=connectrpc" \
		"./$_d"/*.proto
done
