#!/bin/bash
set -euo pipefail

PATH="$PATH:$(go env GOPATH)/bin"
export PATH

_project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)/.."
_envoy_version=1.17.3
_dir="${DIR:-"$_project_root/bin"}"
_target="${TARGET:-"$(go env GOOS)-$(go env GOARCH)"}"

# until m1 macs are supported, fallback to x86 and use rosetta
if [ "$_target" == "darwin-arm64" ]; then
  _target="darwin-amd64"
fi

_url="https://github.com/pomerium/envoy-binaries/releases/download/v${_envoy_version}/envoy-${_target}"

# create the directory if it doesn't exist
mkdir -p "$_dir"

# download the shasum of the binary
curl \
  --compressed \
  --silent \
  --location \
  --output "$_dir/envoy-$_target.sha256" \
  "$_url.sha256"

# if the shasum doesn't match (or the binary doesn't exist), re-download
if ! (cd "$_dir" && shasum -c "envoy-$_target.sha256" >/dev/null 2>&1) ; then
  curl \
    --compressed \
    --silent \
    --location \
    --output "$_dir/envoy-$_target" \
    "$_url"
fi

# save the bare name
cp -f "$_dir/envoy-$_target" "$_dir/envoy"
cp -f "$_dir/envoy-$_target.sha256" "$_dir/envoy.sha256"

# save to the embedded files in the envoy package
cp -f "$_dir/envoy-$_target.sha256" "$_project_root/internal/envoy/files/envoy.sha256"
echo "$_envoy_version" > "$_project_root/internal/envoy/files/envoy.version"
