#!/bin/bash
set -euo pipefail

_pomerium_binary_path="${1?"pomerium binary path is required"}"
_go_os="$(go env GOOS)"
_go_arch="$(go env GOARCH)"

is_musl() {
  ldd /bin/ls | grep musl >/dev/null 2>&1
}

# URLs from: https://tetrate.bintray.com/getenvoy/manifest.json
_envoy_version="1.14.1"
_envoy_build=""
if [ "$_go_os" == linux ] && ! is_musl && [ "$_go_arch" == "amd64" ]; then
  _envoy_build="LINUX_GLIBC"
elif [ "$_go_os" == darwin ] && [ "$_go_arch" == "amd64" ]; then
  _envoy_build="DARWIN"
fi
if [ -z "$_envoy_build" ]; then
  echo "this platform is not supported for embedded envoy"
  exit 1
fi
_envoy_url="$(
  curl --silent "https://tetrate.bintray.com/getenvoy/manifest.json" |
    jq -r '.flavors.standard.versions["'"$_envoy_version"'"].builds["'"$_envoy_build"'"].downloadLocationUrl'
)"

_abs_pomerium_binary_path="$(realpath "$_pomerium_binary_path")"

_wd="/tmp/pomerium-embedded-files"
mkdir -p "$_wd"
(
  cd "$_wd"
  if [ ! -f "envoy-$_envoy_version.tar.xz" ]; then
    echo "downloading $_envoy_url"
    curl --silent --location --output "envoy-$_envoy_version.tar.xz" "$_envoy_url"
  fi
  echo "extracting"
  tar --extract --xz --strip-components=3 --file "envoy-$_envoy_version.tar.xz"
  echo "appending to $_abs_pomerium_binary_path"
  # if this binary already has a zip file appended to it
  if [ -z "$(unzip -z -qq "$_abs_pomerium_binary_path" 2>&1)" ]; then
    zip -A "$_abs_pomerium_binary_path" envoy
  else
    zip envoy.zip envoy
    cat envoy.zip >>"$_abs_pomerium_binary_path"
  fi
  zip -A "$_abs_pomerium_binary_path"
)
