#!/bin/bash
set -euo pipefail

BINARY=$1

ENVOY_VERSION=1.14.2
DIR=$(dirname "${BINARY}")
GOOS=$(echo "${GOOS-}" | cut -d _ -f 1) # goreleaser is fine

GOOS=$(go env GOOS)

if [ "${GOOS}" == "darwin" ]; then
  ENVOY_PLATFORM="darwin"
elif [ "${GOOS}" == "linux" ]; then
  ENVOY_PLATFORM="linux_glibc"
else
  echo "unsupported"
  exit 1
fi

## TODO we should be able to replace this with a utility that consumes
## https://godoc.org/github.com/tetratelabs/getenvoy/pkg/binary/envoy
## https://golang.org/pkg/archive/zip/#Writer.SetOffset
export PATH=$PATH:$(go env GOPATH)/bin
HOME=${DIR} getenvoy fetch standard:${ENVOY_VERSION}/${ENVOY_PLATFORM}
ENVOY_PATH=${DIR}/.getenvoy/builds/standard/${ENVOY_VERSION}/${ENVOY_PLATFORM}/bin
ARCHIVE=${ENVOY_PATH}/envoy.zip

(
  cd "${ENVOY_PATH}"
  zip envoy.zip envoy
)

echo "appending ${ARCHIVE} to ${BINARY}"

if [ "$(unzip -z -qq "$BINARY" 2>&1)" != "" ]; then
  cat "${ARCHIVE}" >>"${BINARY}"
fi
zip -A "${BINARY}"
