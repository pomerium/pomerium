#!/bin/bash

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
	identity
	registry
	session
	user
	testproto
	health
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
	registry
)

for _d in "${_validate_dirs[@]}"; do
	../../scripts/protoc \
		-I "./$_d/" \
		--validate_out="./$_d" \
		--validate_opt="lang=go" \
		--validate_opt="paths=source_relative" \
		"./$_d/"*.proto
done
