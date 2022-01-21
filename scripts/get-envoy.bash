#!/bin/bash
set -euo pipefail

PATH="$PATH:$(go env GOPATH)/bin"
export PATH

_project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)/.."
_envoy_version=1.20.1
_dir="$_project_root/internal/envoy/files"
_target="${TARGET:-"$(go env GOOS)-$(go env GOARCH)"}"

if [ "$_target" == "darwin-arm64" ]; then
  echo "Using local envoy distribution for Apple M1"
  cp -f "$(which envoy)" "$_dir/envoy-$_target"
  (cd internal/envoy/files && sha256sum "$_dir/envoy-$_target" >"$_dir/envoy-$_target.sha256")
  echo "1.21.0-dev" >"$_dir/envoy-$_target.version"
  exit 0
fi

_url="https://github.com/pomerium/envoy-binaries/releases/download/v${_envoy_version}/envoy-${_target}"

curl \
  --compressed \
  --silent \
  --location \
  --time-cond "$_dir/envoy-$_target" \
  --output "$_dir/envoy-$_target" \
  "$_url"

curl \
  --compressed \
  --silent \
  --location \
  --time-cond "$_dir/envoy-$_target.sha256" \
  --output "$_dir/envoy-$_target.sha256" \
  "$_url.sha256"

echo "$_envoy_version" >"$_dir/envoy-$_target.version"
