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

FROM golang:1.19.5-buster@sha256:150a98859da4c88935958d21d4fca1c74a139eac88e1eb2364c8f60d69236ede as build
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
FROM debian:stable@sha256:12931ad2bfd4a9609cf8ef7898f113d67dce8058f0c27f01c90ef7bdd5a61bfb as casource
RUN apt-get update && apt-get install -y ca-certificates
# Remove expired root (https://github.com/pomerium/pomerium/issues/2653)
RUN rm /usr/share/ca-certificates/mozilla/DST_Root_CA_X3.crt && update-ca-certificates

FROM gcr.io/distroless/base:debug@sha256:4f9fe9414e01e5398881db4f30d810e832bcaece5f11f3d09a1e541311b2ce53
ENV AUTOCERT_DIR /data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
COPY --from=casource /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
