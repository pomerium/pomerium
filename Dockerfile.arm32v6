FROM golang:latest as build
WORKDIR /go/src/github.com/pomerium/pomerium
ENV CGO_ENABLED=0
ENV GO111MODULE=on
ENV GOARCH=arm
ENV GOARM=6
# cache depedency downloads
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# build 
RUN make build
RUN touch /config.yaml

FROM gcr.io/distroless/static
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]