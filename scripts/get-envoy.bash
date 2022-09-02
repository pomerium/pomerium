#!/bin/bash
set -euo pipefail

PATH="$PATH:$(go env GOPATH)/bin"
export PATH

_project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)/.."
_envoy_version=1.23.1
_dir="$_project_root/pkg/envoy/files"
_target="${TARGET:-"$(go env GOOS)-$(go env GOARCH)"}"

_url="https://github.com/pomerium/envoy-binaries/releases/download/v${_envoy_version}/envoy-${_target}"

curl \
  --silent \
  --fail \
  --compressed \
  --location \
  --time-cond "$_dir/envoy-$_target" \
  --output "$_dir/envoy-$_target" \
  "$_url"

curl \
  --silent \
  --fail \
  --compressed \
  --location \
  --time-cond "$_dir/envoy-$_target.sha256" \
  --output "$_dir/envoy-$_target.sha256" \
  "$_url.sha256"

echo "$_envoy_version" >"$_dir/envoy-$_target.version"
