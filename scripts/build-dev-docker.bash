#!/bin/bash
set -euxo pipefail

_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
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

(
  cd "$_script_dir"
  env OS=Linux ARCH=x86_64 ./embed-envoy.bash "$_dir/pomerium"
)

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

  # build for minikube
  if command -v minikube >/dev/null 2>&1; then
    eval "$(minikube docker-env --shell=bash)"
    docker build --tag=pomerium/pomerium:dev .
  fi

)
