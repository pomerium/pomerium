FROM golang:1.26.10-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS build-env

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...
RUN go install -v ./...

FROM gcr.io/distroless/base:latest@sha256:44a80dc28b49f47396e72ab2dc644b3f849880335de09625762faed207bb891d
COPY --from=build-env /go/bin/app /
CMD ["/app"]
