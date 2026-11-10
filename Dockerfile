FROM node:24.22.2-bookworm@sha256:8fa96264f302f58bbb13aa7339c541547b56975766ce956c875da149452a3e40 AS ui
WORKDIR /build

COPY .git ./.git
COPY Makefile ./Makefile

# download npm dependencies
COPY ui/package-lock.json ./ui/package-lock.json
COPY ui/package.json ./ui/package.json
RUN make npm-install

# build ui
COPY ./ui/ ./ui/
RUN make build-ui

FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS build
WORKDIR /go/src/github.com/pomerium/pomerium

RUN apt-get update \
    && apt-get -y --no-install-recommends install zip

COPY . .
COPY --from=ui /build/ui/dist ./ui/dist

# build
ARG POMERIUM_OFFICIAL_BUILD=0
RUN --mount=type=cache,target=/go/pkg/mod make build-go NAME=pomerium POMERIUM_OFFICIAL_BUILD=${POMERIUM_OFFICIAL_BUILD}
RUN touch /config.yaml
RUN if [ "${POMERIUM_OFFICIAL_BUILD}" = "1" ]; then \
      cp licenses/POMERIUM-COMMUNITY-LICENSE-1.0.txt /LICENSE; \
    else \
      cp LICENSE /LICENSE; \
    fi

FROM gcr.io/distroless/base-nossl-debian13:debug@sha256:4a1b47e4dc79d5331f6b9265f8933a96351fb6341441902acf8dc8a9a6d25630
ENV AUTOCERT_DIR=/data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /LICENSE /pomerium/LICENSE
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["--config","/pomerium/config.yaml"]
