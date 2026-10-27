FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build-env

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...
RUN go install -v ./...

FROM gcr.io/distroless/base-debian13:latest@sha256:f5e95195e998742ff590b7569bae479accce1226e51ae6c3118954030121cdcb
COPY --from=build-env /go/bin/app /
CMD ["/app"]
