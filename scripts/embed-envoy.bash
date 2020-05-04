#!/bin/bash
set -euo pipefail

_pomerium_binary_path="${1?"pomerium binary path is required"}"
_os="${OS:-"$(uname -s)"}"
_arch="${ARCH:-"$(uname -m)"}"

is_musl() {
  ldd /bin/ls | grep musl >/dev/null 2>&1
}

# URLs from: https://tetrate.bintray.com/getenvoy/manifest.json
_envoy_url_linux="https://dl.bintray.com/tetrate/getenvoy/getenvoy-envoy-1.14.1.p0.g3504d40-1p63.g902f20f-linux-glibc-release-x86_64.tar.xz"
_envoy_url_darwin="https://dl.bintray.com/tetrate/getenvoy/getenvoy-envoy-1.14.1.p0.g3504d40-1p63.g902f20f-darwin-release-x86_64.tar.xz"
_envoy_url=""
if [ "$_os" == Linux ] && ! is_musl && [ "$_arch" == "x86_64" ]; then
  _envoy_url="$_envoy_url_linux"
elif [ "$_os" == Darwin ] && [ "$_arch" == "x86_64" ]; then
  _envoy_url="$_envoy_url_darwin"
fi
if [ -z "$_envoy_url" ]; then
  echo "this platform is not supported for embedded envoy"
  exit 1
fi

_wd="/tmp/pomerium-embedded-files"
mkdir -p "$_wd"
(
  cd "$_wd"
  curl --no-progress-meter -L "$_envoy_url" | tar --extract --xz --strip-components=3
  # if this binary already has a zip file appended to it
  if unzip -z -qq "$_pomerium_binary_path" >/dev/null 2>&1; then
    zip "$_pomerium_binary_path" envoy
  else
    zip envoy.zip envoy
    cat envoy.zip >>"$_pomerium_binary_path"
  fi
  zip -A "$_pomerium_binary_path"
)
