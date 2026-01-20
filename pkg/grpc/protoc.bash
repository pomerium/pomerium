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

../../scripts/protoc -I "./registry/" \
	--validate_out="./registry/" \
	--validate_opt="lang=go" \
	--validate_opt="paths=source_relative" \
	./registry/registry.proto
