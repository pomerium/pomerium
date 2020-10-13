#!/bin/sh

DEBUG_PORT="${DEBUG_PORT:-9999}"
DEBUG_ADDRESS="${DEBUG_ADDRESS:-127.0.0.1}"
/bin/dlv exec /bin/pomerium --api-version=2 --headless --listen="${DEBUG_ADDRESS}:${DEBUG_PORT}" --log --accept-multiclient -- "$@"
