FROM node:lts-bookworm@sha256:ae2f3d4cc65d251352eca01ba668824f651a2ee4d2a37e2efb22649521a483fd AS ui
WORKDIR /build

COPY .git ./.git
COPY Makefile ./Makefile

# download yarn dependencies
COPY ui/yarn.lock ./ui/yarn.lock
COPY ui/package.json ./ui/package.json
RUN make yarn

# build ui
COPY ./ui/ ./ui/
RUN make build-ui

FROM golang:1.23-bookworm@sha256:3149bc5043fa58cf127fd8db1fdd4e533b6aed5a40d663d4f4ae43d20386665f AS build
WORKDIR /go/src/github.com/pomerium/pomerium

RUN apt-get update \
    && apt-get -y --no-install-recommends install zip

# cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /build/ui/dist ./ui/dist

# build
RUN make build-go NAME=pomerium
RUN touch /config.yaml

FROM gcr.io/distroless/base-debian12:debug@sha256:3a59a8d10471fc8487fd2ca93746b0195ed4c3236c14fe8412cf7b2ec4b8c1f3
ENV AUTOCERT_DIR=/data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
