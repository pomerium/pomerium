FROM node:24.22.3-bookworm@sha256:6b33b0be1647d1a577f9cebb6c8fc2587cc02c98c9956af8d0289df1791a3d10 AS ui
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

FROM golang:1.27.4-bookworm@sha256:ce59b41415e2524ae99926fe1f37ce48ba8c194dcbd2a56a65436cdcefa2bd34 AS build
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
