FROM node:22.22.2-bookworm@sha256:7e791fc54bd02fc89fd4fb39eb37e5bea753c75679c8022478d81679367d995a AS ui
WORKDIR /build

COPY .git ./.git
COPY Makefile ./Makefile

# install npm 11.12.1 (npm 10 ignores min-release-age)
RUN npm_dir="$(npm root -g)/npm" && rm -rf "$npm_dir" && mkdir -p "$npm_dir" \
    && curl -fsSL "https://registry.npmjs.org/npm/-/npm-11.12.1.tgz" | tar xz --strip-components=1 -C "$npm_dir"

# download npm dependencies
COPY ui/package-lock.json ./ui/package-lock.json
COPY ui/package.json ./ui/package.json
COPY ui/.npmrc ./ui/.npmrc
RUN make npm-install

# build ui
COPY ./ui/ ./ui/
RUN make build-ui

FROM golang:1.26.1-bookworm@sha256:8e8aa801e8417ef0b5c42b504dd34db3db911bb73dba933bd8bde75ed815fdbb AS build
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

FROM gcr.io/distroless/base-debian12:debug@sha256:1f8759794cab46f0673e14afc03e3623cbd803b683abf7e3143fd041cc2e89f7
ENV AUTOCERT_DIR=/data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["--config","/pomerium/config.yaml"]
