FROM golang:latest as build
WORKDIR /go/src/github.com/pomerium/pomerium
ENV CGO_ENABLED=0
ENV GO111MODULE=on
# cache depedency downloads
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# build 
RUN make build

FROM gcr.io/distroless/static
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
CMD ["/bin/pomerium"]
