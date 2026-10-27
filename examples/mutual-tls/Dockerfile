FROM golang:1.26.10-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS build-env

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...
RUN go install -v ./...

# Remove this stage once distroless Debian 12 ships the corrected CA bundle.
FROM --platform=$BUILDPLATFORM debian:bookworm@sha256:854dd8ab51d62866dbd8f5431d15ce77b12983a2a4a1e1fe43a2395dc7ef9f61 AS distroless-ca-certificates
RUN --mount=type=tmpfs,target=/var/cache/apt \
    --mount=type=tmpfs,target=/var/lib/apt/lists \
    apt-get -qq update \
    && DEBIAN_FRONTEND=noninteractive apt-get -qq install --no-install-recommends -y ca-certificates \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge '20250419~deb12u2' \
    && mkdir -p /out/etc/ssl/certs /out/usr/share/doc/ca-certificates /out/var/lib/dpkg/status.d \
    && cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ \
    && cp /usr/share/doc/ca-certificates/copyright /out/usr/share/doc/ca-certificates/ \
    && dpkg-query -s ca-certificates | grep -v '^Status:' > /out/var/lib/dpkg/status.d/ca-certificates \
    && cp /var/lib/dpkg/info/ca-certificates.md5sums /out/var/lib/dpkg/status.d/

FROM gcr.io/distroless/base:latest@sha256:44a80dc28b49f47396e72ab2dc644b3f849880335de09625762faed207bb891d
COPY --from=distroless-ca-certificates --chown=0:0 /out/ /
COPY --from=build-env /go/bin/app /
CMD ["/app"]
