FROM golang:1.25.7-bookworm@sha256:38342f3e7a504bf1efad858c18e771f84b66dc0b363add7a57c9a0bbb6cf7b12 AS build-env

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...
RUN go install -v ./...

FROM gcr.io/distroless/base:latest@sha256:b0216a38315e7d4e14a70338f4bcfdf622bcd2ca2f3fcb48de446c4bb51f7243
COPY --from=build-env /go/bin/app /
CMD ["/app"]
