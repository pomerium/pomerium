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

FROM golang:1.19.2-buster@sha256:403f38941d7643bc91fad0227ebee6ddd80159b79fc339f6702271a2679a5f11 as build
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
FROM debian:stable@sha256:9583740c100697a7dd186b80198a66ad24927e03437414559f90e0ed2639346e as casource
RUN apt-get update && apt-get install -y ca-certificates
# Remove expired root (https://github.com/pomerium/pomerium/issues/2653)
RUN rm /usr/share/ca-certificates/mozilla/DST_Root_CA_X3.crt && update-ca-certificates

FROM gcr.io/distroless/base:debug@sha256:856944e81ffb36babf549e52933e1c09379372135a9b73a97f275fa2973de13a
ENV AUTOCERT_DIR /data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
COPY --from=casource /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
