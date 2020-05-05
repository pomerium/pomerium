#!/bin/bash
set -euxo pipefail

_dir=/tmp/pomerium-dev-docker
mkdir -p "$_dir"

# build linux binary
env GOOS=linux \
  GOARCH=amd64 \
  CGO_ENABLED=0 \
  GO111MODULE=on \
  go build \
  -ldflags "-s -w" \
  -o "$_dir/pomerium" \
  ./cmd/pomerium

# build docker image
(

  cd $_dir
  cat <<EOF >config.yaml

EOF
  cat <<EOF >Dockerfile
FROM gcr.io/distroless/base:debug
WORKDIR /pomerium
COPY pomerium /bin/pomerium
COPY config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
EOF
  docker build --tag=pomerium/pomerium:dev .
  kind load docker-image pomerium/pomerium:dev
)
