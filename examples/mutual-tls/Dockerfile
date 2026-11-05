FROM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build-env

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...
RUN go install -v ./...

FROM gcr.io/distroless/base:latest@sha256:44a80dc28b49f47396e72ab2dc644b3f849880335de09625762faed207bb891d
COPY --from=build-env /go/bin/app /
CMD ["/app"]
