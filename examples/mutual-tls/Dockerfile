FROM golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514 AS build-env

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...
RUN go install -v ./...

FROM gcr.io/distroless/base:latest@sha256:b0216a38315e7d4e14a70338f4bcfdf622bcd2ca2f3fcb48de446c4bb51f7243
COPY --from=build-env /go/bin/app /
CMD ["/app"]
