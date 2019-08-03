FROM golang:latest as build
WORKDIR /go/src/github.com/pomerium/pomerium
# docker build --build-arg ARCH=arm --build-arg ARM=7 .
# frustratingly not supported by dockerhub automated builds though
ARG ARCH=amd64
ARG ARM=7  

ENV CGO_ENABLED=0
ENV GOPROXY=https://goproxy.io

ENV GO111MODULE=on
ENV GOARCH=${ARCH}
ENV GOARM=${ARM}
# cache depedency downloads
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# build
RUN make
RUN touch /config.yaml

FROM gcr.io/distroless/static
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
