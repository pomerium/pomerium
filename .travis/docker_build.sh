#!/bin/sh -e

FULL_IMAGE_NAME=${1:-pomerium/pomerium}
DOCKERFILE=${2:-Dockerfile}

docker build -t "${FULL_IMAGE_NAME}" -f "${DOCKERFILE}" .
