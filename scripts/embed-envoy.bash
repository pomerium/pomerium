#!/bin/bash
set -euo pipefail

BINARY=$1

ENVOY_VERSION=1.16.2
DIR=$(dirname "${BINARY}")
TARGET="${TARGET:-"$(go env GOOS)_$(go env GOARCH)"}"

if [[ "${TARGET}" == darwin_* ]]; then
  ENVOY_PLATFORM="darwin"
elif [[ "${TARGET}" == linux_* ]]; then
  ENVOY_PLATFORM="linux_glibc"
else
  echo "unsupported TARGET: ${TARGET}"
  exit 1
fi

## TODO we should be able to replace this with a utility that consumes
## https://godoc.org/github.com/tetratelabs/getenvoy/pkg/binary/envoy
## https://golang.org/pkg/archive/zip/#Writer.SetOffset
export PATH=$PATH:$(go env GOPATH)/bin
if [ "$TARGET" == "linux_arm64" ]; then
  ENVOY_PATH="$DIR/$TARGET"
  mkdir -p "$ENVOY_PATH"
  curl -L -o "$ENVOY_PATH/envoy" https://github.com/pomerium/envoy-binaries/releases/download/v${ENVOY_VERSION}/envoy-linux-arm64
else
  env HOME="${DIR}" getenvoy fetch standard:${ENVOY_VERSION}/${ENVOY_PLATFORM}
  ENVOY_PATH=${DIR}/.getenvoy/builds/standard/${ENVOY_VERSION}/${ENVOY_PLATFORM}/bin
fi
ARCHIVE="${ENVOY_PATH}/envoy.zip"

(
  cd "${ENVOY_PATH}"
  zip envoy.zip envoy
)

echo "appending ${ARCHIVE} to ${BINARY}"

if [ "$(unzip -z -qq "$BINARY" 2>&1)" != "" ]; then
  cat "${ARCHIVE}" >>"${BINARY}"
fi
zip -A "${BINARY}"
