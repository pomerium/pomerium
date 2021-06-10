#!/bin/bash
set -euo pipefail

PATH="$PATH:$(go env GOPATH)/bin"
export PATH

_envoy_version=1.17.3
_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)/../internal/envoy/bin"
_target="${TARGET:-"$(go env GOOS)-$(go env GOARCH)"}"

# until m1 macs are supported, fallback to x86 and use rosetta
if [ "$_target" == "darwin-arm64" ]; then
  _target="darwin-amd64"
fi

mkdir -p "$_dir"

is_command() {
    command -v "$1" >/dev/null
}

hash_sha256() {
    TARGET=${1:-/dev/stdin}
    if is_command gsha256sum; then
        hash=$(gsha256sum "$TARGET") || return 1
        echo "$hash" | cut -d ' ' -f 1
    elif is_command sha256sum; then
        hash=$(sha256sum "$TARGET") || return 1
        echo "$hash" | cut -d ' ' -f 1
    elif is_command shasum; then
        hash=$(shasum -a 256 "$TARGET" 2>/dev/null) || return 1
        echo "$hash" | cut -d ' ' -f 1
    elif is_command openssl; then
        hash=$(openssl -dst openssl dgst -sha256 "$TARGET") || return 1
        echo "$hash" | cut -d ' ' -f a
    else
        echo "hash_sha256 unable to find command to compute sha-256 hash"
        return 1
    fi
}

_url="https://github.com/pomerium/envoy-binaries/releases/download/v${_envoy_version}/envoy-${_target}"

# retrieve the redirect url
_url="$(
curl \
    --silent \
    --head \
    --write-out '%{redirect_url}' \
    --output /dev/null \
    "$_url"
)"


# check the etag to avoid re-downloading
if [ -f "$_dir/envoy.etag" ]; then
    _response_code="$(
    curl \
        --silent \
        --header "If-None-Match: \"$(cat "$_dir/envoy.etag")\"" \
        --head \
        --write-out '%{response_code}' \
        --output /dev/null \
        "$_url"
    )"
    if [ "$_response_code" == "304" ]; then
      exit 0
    fi
fi

curl \
    --silent \
    --compressed \
    --etag-save "$_dir/envoy.etag" \
    --output "$_dir/envoy" \
    "$_url"

hash_sha256 "$_dir/envoy" >"$_dir/envoy.sha256"
