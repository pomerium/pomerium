FROM node:26.13.1-bookworm@sha256:b7087bc4d973034b30854b378ba107f9fab622b47514cb7e2592e41b8bab8d49 AS build-ui
WORKDIR /build

COPY ui/package.json ./ui/package-lock.json ./
RUN \
  --mount=type=cache,target=/root/.npm \
  npm ci

COPY ./ui/ ./
RUN npm run build

FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
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
