#!/bin/bash
set -euo pipefail

PATH="$PATH:$(go env GOPATH)/bin"
export PATH

_project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)/.."
_dir="$_project_root/pkg/envoy/files"

for _target in darwin-amd64 darwin-arm64 linux-amd64 linux-arm64; do
  _envoy_version=1.28.2
  if [[ "$_target" == darwin* ]]; then
    _envoy_version='1.28.0'
  fi
  _url="https://github.com/pomerium/envoy-binaries/releases/download/v${_envoy_version}/envoy-${_target}"

  curl \
    --silent \
    --fail \
    --show-error \
    --compressed \
    --location \
    --time-cond "$_dir/envoy-$_target" \
    --output "$_dir/envoy-$_target" \
    "$_url" &

  curl \
    --silent \
    --fail \
    --show-error \
    --compressed \
    --location \
    --time-cond "$_dir/envoy-$_target.sha256" \
    --output "$_dir/envoy-$_target.sha256" \
    "$_url.sha256" &

  echo "$_envoy_version" >"$_dir/envoy-$_target.version"
done

wait
