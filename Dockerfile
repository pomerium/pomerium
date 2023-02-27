FROM node:16@sha256:68e34cfcd8276ad531b12b3454af5c24cd028752dfccacce4e19efef6f7cdbe0 as ui
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

FROM golang:1.20.1-buster@sha256:d99d3614cfc6bc0f7e4d96b54682d403f2a7c2ab82c6001a7701e937dd8f4d6d as build
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

# build our own root trust store from current stable
FROM debian:stable@sha256:7b16406f7f0918371637674373850eb53737505b1ecbc723ce992dd19701cffb as casource
RUN apt-get update && apt-get install -y ca-certificates
# Remove expired root (https://github.com/pomerium/pomerium/issues/2653)
RUN rm /usr/share/ca-certificates/mozilla/DST_Root_CA_X3.crt && update-ca-certificates

FROM gcr.io/distroless/base:debug@sha256:5812871f5d87d6d4c226c536be70f7a8232a77230675b4b574c9866c8dc982fa
ENV AUTOCERT_DIR /data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
COPY --from=casource /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
