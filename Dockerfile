FROM golang:alpine as build
RUN apk --update --no-cache add ca-certificates git make
ENV CGO_ENABLED=0
ENV GO111MODULE=on

WORKDIR /go/src/github.com/pomerium/pomerium
COPY . .

RUN make

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
CMD ["/bin/pomerium"]
