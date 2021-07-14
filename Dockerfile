# hadolint ignore=DL3007
FROM golang:latest as build
WORKDIR /go/src/github.com/pomerium/pomerium

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get -y --no-install-recommends install zip

# cache depedency downloads
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# build
RUN make build-deps && \
    make build NAME=pomerium && \
    make build NAME=pomerium-cli && \
    touch /config.yaml

FROM gcr.io/distroless/base:debug
ENV AUTOCERT_DIR /data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
