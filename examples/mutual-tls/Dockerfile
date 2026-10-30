FROM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS build-env

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...
RUN go install -v ./...

FROM gcr.io/distroless/base-debian13:latest@sha256:f5e95195e998742ff590b7569bae479accce1226e51ae6c3118954030121cdcb
COPY --from=build-env /go/bin/app /
CMD ["/app"]
