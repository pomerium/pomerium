FROM golang:alpine as build
RUN apk --update --no-cache add ca-certificates git make
ENV CGO_ENABLED=0
ENV GO111MODULE=on

WORKDIR /go/src/github.com/pomerium/pomerium

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
# docker build --build-arg ARCH=arm --build-arg ARM=7 .
ARG ARCH=amd64
ARG ARM=7
ENV GOARCH=${ARCH}
ENV GOARM=${ARM}
RUN make

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
CMD ["/bin/pomerium"]
