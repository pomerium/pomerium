FROM node:16 as ui
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

FROM golang:1.17-buster as build
WORKDIR /go/src/github.com/pomerium/pomerium

RUN apt-get update \
    && apt-get -y --no-install-recommends install zip

# cache depedency downloads
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /build/ui/dist ./ui/dist

# build
RUN make build-go NAME=pomerium
RUN touch /config.yaml

# build our own root trust store from current stable
FROM debian:stable as casource
RUN apt-get update && apt-get install -y ca-certificates
# Remove expired root (https://github.com/pomerium/pomerium/issues/2653)
RUN rm /usr/share/ca-certificates/mozilla/DST_Root_CA_X3.crt && update-ca-certificates

FROM gcr.io/distroless/base:debug-${TARGETARCH:-amd64}
ENV AUTOCERT_DIR /data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
COPY --from=casource /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
