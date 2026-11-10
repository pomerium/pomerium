FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS build-env

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...
RUN go install -v ./...

FROM gcr.io/distroless/base-debian13:latest@sha256:f5e95195e998742ff590b7569bae479accce1226e51ae6c3118954030121cdcb
COPY --from=build-env /go/bin/app /
CMD ["/app"]
