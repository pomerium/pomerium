#!/bin/bash
set -euo pipefail

BINARY=$1
DIR=$(dirname "${BINARY}")

(
  cd "$DIR"
  zip envoy.zip envoy
)

echo "appending $DIR/envoy.zip to ${BINARY}"

if [ "$(unzip -z -qq "$BINARY" 2>&1)" != "" ]; then
  cat "$DIR/envoy.zip" >>"${BINARY}"
fi
zip -A "${BINARY}"
