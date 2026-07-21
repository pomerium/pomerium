#!/bin/bash

function join_by() {
	local IFS="$1"
	shift
	echo "$*"
}

function replace-in-file() {
	local _search="${1?"search is required"}"
	local _replace="${2?"replace is required"}"
	local _file="${3?"file is required"}"
	local _tmp

	_tmp="$(mktemp)"
	sed -E 's/'"$_search"'/'"$_replace"'/g' "$_file" >"$_tmp"
	mv "$_tmp" "$_file"
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

for _d in "${_connect_dirs[@]}"; do
	../../scripts/protoc \
		-I "./$_d/" \
		--connect-go_out="./$_d/" \
		--connect-go_opt="paths=source_relative" \
		--connect-openapi_out="./$_d/" \
		--connect-openapi_opt="content-types=json,trim-unused-types,features=connectrpc;gnostic;protovalidate" \
		"./$_d"/*.proto
	replace-in-file "^info:" "info:\n  version: $(git describe --tags --abbrev=0 --match=v*)" "$_d/config.openapi.yaml"
done
