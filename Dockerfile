FROM node:26.13.1-bookworm@sha256:893ea48106e988a5f91e69629d6472600daa9d0494adf7db87eb0b886ce82255 AS build-ui
WORKDIR /build

COPY ui/package.json ./ui/package-lock.json ./
RUN \
  --mount=type=cache,target=/root/.npm \
  npm ci

COPY ./ui/ ./
RUN npm run build

FROM golang:1.27.4-bookworm@sha256:ce59b41415e2524ae99926fe1f37ce48ba8c194dcbd2a56a65436cdcefa2bd34 AS build
ARG POMERIUM_OFFICIAL_BUILD=0
ENV POMERIUM_OFFICIAL_BUILD=${POMERIUM_OFFICIAL_BUILD}
WORKDIR /go/src/github.com/pomerium/pomerium

COPY . .
COPY --from=build-ui /build/dist ./ui/dist

# build
RUN \
  --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  make build-go
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
