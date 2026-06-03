FROM golang:1.26.4-bookworm@sha256:5d2b868674b57c9e48cdd39e891acce4196b6926ca6d11e9c270a8f85106203d AS build-env

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...
RUN go install -v ./...

FROM gcr.io/distroless/base:latest@sha256:b0216a38315e7d4e14a70338f4bcfdf622bcd2ca2f3fcb48de446c4bb51f7243
COPY --from=build-env /go/bin/app /
CMD ["/app"]
