FROM golang:latest as build
WORKDIR /go/src/github.com/pomerium/pomerium
ENV CGO_ENABLED=0
ENV GO111MODULE=on
ENV GOARCH=arm64
# cache depedency downloads
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# build 
RUN make build
RUN touch /config.yaml

FROM arm64v8/alpine
WORKDIR /pomerium
COPY --from=multiarch/qemu-user-static /usr/bin/qemu-aarch64-static /usr/bin/
RUN apk --no-cache add ca-certificates
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]