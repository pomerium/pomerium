#!/bin/bash
set -euo pipefail

_pomerium_binary_path="${1?"pomerium binary path is required"}"
_go_os="$(go env GOOS)"
_go_arch="$(go env GOARCH)"

is_musl() {
  ldd /bin/ls | grep musl >/dev/null 2>&1
}

# URLs from: https://tetrate.bintray.com/getenvoy/manifest.json
_envoy_url_linux="https://dl.bintray.com/tetrate/getenvoy/getenvoy-envoy-1.14.1.p0.g3504d40-1p63.g902f20f-linux-glibc-release-x86_64.tar.xz"
_envoy_url_darwin="https://dl.bintray.com/tetrate/getenvoy/getenvoy-envoy-1.14.1.p0.g3504d40-1p63.g902f20f-darwin-release-x86_64.tar.xz"
_envoy_url=""
if [ "$_go_os" == linux ] && ! is_musl && [ "$_go_arch" == "amd64" ]; then
  _envoy_url="$_envoy_url_linux"
elif [ "$_go_os" == darwin ] && [ "$_go_arch" == "amd64" ]; then
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
  echo "downloading $_envoy_url"
  curl --no-progress-meter -L "$_envoy_url" | tar --extract --xz --strip-components=3
  echo "appending to $_pomerium_binary_path"
  # if this binary already has a zip file appended to it
  if unzip -z -qq "$_pomerium_binary_path" >/dev/null 2>&1; then
    zip "$_pomerium_binary_path" envoy >/dev/null 2>&1
  else
    zip envoy.zip envoy >/dev/null 2>&1
    cat envoy.zip >>"$_pomerium_binary_path"
  fi
  zip -A "$_pomerium_binary_path" >/dev/null 2>&1
)
