FROM node:lts-bookworm@sha256:f3299f16246c71ab8b304d6745bb4059fa9283e8d025972e28436a9f9b36ed24 as ui
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

FROM golang:1.22.1-bookworm@sha256:6699d2852712f090399ccd4e8dfd079b4d55376f3ab3aff5b2dc8b7b1c11e27e as build
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

FROM gcr.io/distroless/base-debian12:debug@sha256:dd7d3956ac928c2beef8dd10c7d81cff73926ed4a281906f71e1a4e62ed9fedd
ENV AUTOCERT_DIR /data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
