FROM node:lts-bookworm@sha256:d367fd3fce932a9d3bc3816c23f85313d9b44e58e1fed49ef90a10c4b99409e8 AS ui
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

FROM golang:1.25.1-bookworm@sha256:028d35aae29e3e768a7330f4622af402b45e0be58ff5acd49e1eb4f9940f83e0 AS build
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

FROM gcr.io/distroless/base-debian12:debug@sha256:0d30cde8cd133aa8b8a967bb22bdb3fbfeb4daf413cce46b7149c4d4672dfe1e
ENV AUTOCERT_DIR=/data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
