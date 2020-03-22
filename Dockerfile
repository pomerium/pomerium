FROM golang:latest as build
WORKDIR /go/src/github.com/pomerium/pomerium
RUN touch /config.yaml
FROM gcr.io/distroless/static
WORKDIR /pomerium
COPY --from=build /config.yaml /pomerium/config.yaml
COPY pomerium /bin/pomerium
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]