FROM node:lts-bookworm@sha256:bf0ef0687ffbd6c7742e1919177826c8bf1756a68b51f003dcfe3a13c31c65fe as ui
WORKDIR /build

COPY .git ./.git
COPY Makefile ./Makefile

# download yarn dependencies
COPY ui/yarn.lock ./ui/yarn.lock
COPY ui/package.json ./ui/package.json
RUN make yarn

# build ui
COPY ./ui/ ./ui/
RUN make build-ui

FROM golang:1.22.2-bookworm@sha256:3c7ad81405250a6b8027c7c9c2a9ab23cd8d4f9870994bf350ee6045704d47a5 as build
WORKDIR /go/src/github.com/pomerium/pomerium

RUN apt-get update \
    && apt-get -y --no-install-recommends install zip

# cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /build/ui/dist ./ui/dist

# build
RUN make build-go NAME=pomerium
RUN touch /config.yaml

FROM gcr.io/distroless/base-debian12:debug@sha256:e0cc8fa0ed6c46f7f019678218f8b7efdc7df09638ee49f586fb4f0fdf8b09ae
ENV AUTOCERT_DIR /data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
