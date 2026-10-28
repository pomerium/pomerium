FROM node:24.22.1-bookworm@sha256:6449e19d8184d84062525b6a7524def03146c2cb04a7f08b076680d0e8e4240a AS ui
WORKDIR /build

COPY .git ./.git
COPY Makefile ./Makefile

# download npm dependencies
COPY ui/package-lock.json ./ui/package-lock.json
COPY ui/package.json ./ui/package.json
RUN make npm-install

# build ui
COPY ./ui/ ./ui/
RUN make build-ui

FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
WORKDIR /go/src/github.com/pomerium/pomerium

RUN apt-get update \
    && apt-get -y --no-install-recommends install zip

COPY . .
COPY --from=ui /build/ui/dist ./ui/dist

# build
RUN --mount=type=cache,target=/go/pkg/mod make build-go NAME=pomerium
RUN touch /config.yaml

FROM gcr.io/distroless/base-nossl-debian13:debug@sha256:d085c34ea66f46cdd1ff439c01f88c6875f6f49adeb2c1fcc7a22d33e1af515e
ENV AUTOCERT_DIR=/data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["--config","/pomerium/config.yaml"]
